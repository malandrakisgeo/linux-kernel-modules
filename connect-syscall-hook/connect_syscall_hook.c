#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/inet.h>
//#include <linux/syscalls.h>


MODULE_AUTHOR("George Malandrakis");
MODULE_DESCRIPTION("Connection tracker at the syscall level");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");


/*TODO: Use the following structure to save the data to a file
 */
typedef struct connected_ips{
	unsigned int ipv6; //zero if IPv4 
    unsigned short port;
    unsigned char ip[16]; //IPv4 or IPv6
	struct connected_ips *previous;
	struct connected_ips *next;
}connected_ips;

struct connected_ips* first;
struct connected_ips* last;

static struct kprobe kp = {
    /* Using __x64_sys_connect leads to "kernel NULL pointer dereference", 
     * as I realized after like a dozen hours trying to find the mistake.
     */
    .symbol_name    = "__sys_connect", 
    .flags = KPROBE_FLAG_DISABLED
};


void print_ip_v4(unsigned char bytes[])  
{
    printk("ipv4: %d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void print_ip_v6(unsigned char bytes[16])  //Special thanks to Wernsey from stackoverflow and syohex from github!
{
  
    printk("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
	       bytes[0],  bytes[1],
	       bytes[2],  bytes[3],
	       bytes[4],  bytes[5],
	       bytes[6],  bytes[7],
	       bytes[8],  bytes[9],
	       bytes[10], bytes[11],
	       bytes[12], bytes[13],
	       bytes[14], bytes[15]);      
}

void int_to_ipv4_char(unsigned int ip,  unsigned char* bytes)  
{
    int i = 0;
    for(i = 0; i<4;i++){
      *bytes = (ip >> 8*i) & 0xFF;
      ++bytes;
    }

    return;
}

void pointer_to_array(unsigned char* dst, unsigned char* src){
    int i = 0;
    while(src!=0x0 && i<16){
        *dst = *src;
        ++src;
        ++dst;
        ++i;
    }
    
}

void track_ip_addresses(struct sockaddr *addr, struct connected_ips *ips){

    if (addr->sa_family == AF_INET) {
        ips->ipv6 = 0;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        if(addr_in==NULL){
            return;}
            
        ips->port =  ntohs(addr_in->sin_port);
        int_to_ipv4_char(ntohl(addr_in->sin_addr.s_addr), ips->ip);        
        //pointer_to_array(ips->ip, bytes);
    }
    if (addr->sa_family == AF_INET6) {
        ips->ipv6 = 1;
        struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)addr;
        if(addr_in==NULL){
            return;}
        ips->port = addr_in->sin6_port;
        pointer_to_array(ips->ip, addr_in->sin6_addr.s6_addr); //newest
        print_ip_v6(addr_in->sin6_addr.s6_addr);
    }

}



static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
   struct sockaddr *addr;
   struct connected_ips *ips;

    /* 
     * We only are interested in the second argument. 
     * The first six args are stored in the registers on x86-64 at rdi, rsi, rdx, rcx, r8, r9
     */
   if(p==NULL || regs==NULL || regs->si == NULL ){
       return 0;
   }
   
    addr = (struct sockaddr *) (regs->si);
    if(addr == NULL || (addr->sa_family != AF_INET6 && addr->sa_family != AF_INET)){
        return 0;
    }
    ips = (struct connected_ips*) kzalloc(sizeof(connected_ips), GFP_KERNEL);

    //ips->when = ktime_get_seconds(); TODO
    track_ip_addresses(addr, ips);
    
    last->next = ips;
    ips->previous = last;
    last = ips;
    
    return 0;
    
}

static int __init connect_hook_init(void)
{
    int ret;
    
 	first = (struct connected_ips*) kzalloc(sizeof(connected_ips), GFP_KERNEL);
    last = first;
    kp.pre_handler = handler_pre;
    
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    enable_kprobe(&kp);
    return 0;
}

void print_ips(struct connected_ips *ips){
    if(ips==NULL || ips->ip==NULL){
        return;
    }
    if(ips->ipv6 == 1){
        print_ip_v6(ips->ip);
    }else{
        print_ip_v4(ips->ip);
    }
        
}

static void __exit connect_hook_exit(void)
{
    connected_ips* next;
    
    next = first;
    if(next->next){
        next = next->next;
    }else{
        kfree_sensitive(next);
        next = 0x0;
    }

	while(next){
        if(next->ip != NULL){
            //print_ips(next); //uncomment for testing
        }
		kfree_sensitive(next->previous); //aka kzalloc
		next = next->next;
	}
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}



module_init(connect_hook_init);
module_exit(connect_hook_exit);
