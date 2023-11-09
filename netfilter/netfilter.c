#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/pid.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_AUTHOR("George Malandrakis");
MODULE_DESCRIPTION("Netfilter");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static unsigned int hook_out_fn(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state) {
    struct pid *my_pid;
    struct iphdr *iph;
    char bf[TASK_COMM_LEN];  // trust me bro

    if (skb->protocol != htons(ETH_P_IP) &&
        skb->protocol != htons(ETH_P_IPV6)) {
        printk("Packet with non-ip protocol!");
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        iph = ip_hdr(skb);
        printk("Connected to: %pI4\n", &iph->daddr);

        if (skb->sk && skb->sk->sk_socket && skb->sk->sk_socket->file) {
            struct task_struct *tsk;
            my_pid = skb->sk->sk_socket->file->f_owner.pid;
            tsk = get_pid_task(my_pid, PIDTYPE_PID);

            if (tsk != NULL && tsk->mm != NULL) {  // user process
                get_task_comm(bf, tsk);
                printk("Name: %s", bf);
            }
        }
    }

    return NF_ACCEPT;
}

static unsigned int hook_in_fn(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;
    int port;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        port = ntohs(udph->dest);
        if (port == 53 || port == 8085) {
            return NF_ACCEPT;
        }
        printk("UDP packet rejected");
    }

    return NF_DROP;
}

static struct nf_hook_ops out_hook = {.hook = hook_out_fn,
                                      .hooknum = NF_INET_LOCAL_OUT,
                                      .pf = PF_INET,
                                      .priority = NF_IP_PRI_FILTER};

static struct nf_hook_ops in_hook = {.hook = hook_in_fn,
                                     .hooknum = NF_INET_LOCAL_IN,
                                     .pf = PF_INET,
                                     .priority = NF_IP_PRI_FILTER};

int __init netfilter_init(void) {
    int err;
    err = nf_register_net_hook(&init_net, &out_hook);
    if (err < 0) {
        printk("Error when registering out_hook");
        return err;
    }

    err = nf_register_net_hook(&init_net, &in_hook);

    if (err < 0) {
        printk("Error when registering in_hook");
        nf_unregister_net_hook(&init_net, &out_hook);
    }
    return err;
}

void __exit netfilter_exit(void) {
    nf_unregister_net_hook(&init_net, &in_hook);
    nf_unregister_net_hook(&init_net, &out_hook);
}

module_init(netfilter_init);
module_exit(netfilter_exit);
