#define __KERNEL__
#define MODULE
#include <linux/ip.h>             
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/netdevice.h>      
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/skbuff.h>         
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>

     
//NF_INET_POST_ROUTING
unsigned short checksum(unsigned short *addr);
static struct nf_hook_ops netfilter_ops_out;

//struct sk_buff *sock_buff;                           
struct iphdr *ip_header;
unsigned short new_tos;

unsigned int set_DSCP(unsigned int hooknum,
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
  
  printk(KERN_ALERT "Inside set_DSCP \n");
  //assign socket buffer to global var
  	   
	if(skb == NULL)
		printk("sock_buff not initialized\n");
  //check for valid socket buffer. If not, allow packet through
	  if(!skb) { 
	    return NF_ACCEPT; 
	  }  

  //assign to the IP header
  ip_header = (struct iphdr *)ip_hdr(skb);
  //check to make sure the packet is an ip packet. If not, allow packet through
  if(!ip_header) {
   return NF_ACCEPT;
  }
  //if(ip_header ==NULL)
	//printk("ip_hdr not working\n");

  //----------------- Let's do DSCP/TOS stuff ---------------
  //check that packet protocol is TCP
  //ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_ICMP
  if (1 ) {

    printk("ICMP/TCP Packet detected\n");
    printk(KERN_ALERT " The tos bits are : %d\n" , (int)ip_header->tos);
    
    //test checksum method by calculating the original checksum
   // int orig_checksum = checksum((unsigned short *) ip_header); 
	if (skb_is_nonlinear(skb)) {
	    if (skb_linearize(skb) != 0) {
	        return NF_DROP;
	    }
	    ip_header = ip_hdr(skb);
	    //tcph = (void *)iph + (iph->ihl << 2);
	}

  

   	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	printk(KERN_ALERT " The actual original checksum is: %04x", (unsigned short) ip_header->check);
        ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);  	
	printk(KERN_ALERT " The calculated checksum is: %04x", (unsigned short) ip_header->check);

    //value of the codepoint for Expedited Forwarding PHB (EF)
    new_tos = 0x2e;
    //set TOS in the ip header
    ip_header->tos = new_tos;

    //check value of TOS in packet header
    printk(KERN_ALERT " The tos bits are : %d\n" , (int)ip_header->tos);
    if (skb_is_nonlinear(skb)) {
	    if (skb_linearize(skb) != 0) {
	        return NF_DROP;
	    }
	    ip_header = ip_hdr(skb);
	    //tcph = (void *)iph + (iph->ihl << 2);
	}

  

   	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	printk(KERN_ALERT " The actual original checksum is: %04x", (unsigned short) ip_header->check);
        ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);  	
	printk(KERN_ALERT " The calculated checksum is: %04x", (unsigned short) ip_header->check);
 

    //-------- recompute ipv4 checksum so the header will not be seen as corrupted -------
   // int new_checksum = checksum((unsigned short *) ip_header);         

    //set checksum in header to the newly calculated one
    //ip_header->check = new_checksum;

    //printk(KERN_ALERT " New expected checksum is: %04x", (unsigned short) checksum);
    //printk(KERN_ALERT " The new checksum is: %04x", (unsigned short) ip_header->check);

    //allow packet to continue
    return NF_ACCEPT;
}
}


int init_module1(void) {
  printk(KERN_ALERT " Initialization Started \n");

  netfilter_ops_out.hook = set_DSCP;
  netfilter_ops_out.pf = PF_INET;        
  netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
  netfilter_ops_out.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&netfilter_ops_out);
  
  printk(KERN_ALERT "hook functions registered\n");

  return 0;
}


void cleanup_module1(void) { 
  nf_unregister_hook(&netfilter_ops_out); 

  printk(KERN_ALERT "hook functions registered\n");
}

/*
 * modified sample code from RFC 1071 to calculate ipv4 checksum
 */
unsigned short checksum(unsigned short *addr) {
    unsigned long sum = 0;
    int count = 20; //number of bytes in ipv4 header

    while( count > 1 )  {
       // This is the inner loop 
       if(count == 10)
	{
	count-= 2;
	continue;}

       sum += *(unsigned short *) addr++;
       count -= 2;
    }

         //  Add left-over byte, if any 
    if( count > 0 )
       sum += *(unsigned char *) addr;

    // Fold 32-bit sum to 16 bits 
    while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    
    int checksum = ~sum; 

    return (unsigned short) checksum;
}

module_init(init_module1);
module_exit(cleanup_module1);
