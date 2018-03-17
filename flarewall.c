#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>


#include "fw_helper.c"
//#include "ip_nat_standalone.c"
#include "nf_nat_standalone.c"

/****************************************************/
MODULE_LICENSE("GPL v3.0");

MODULE_DESCRIPTION("Flarewall");

MODULE_AUTHOR("Kushagra Choudhary/Pinpwn");
/****************************************************/

//#define PROCF_MAX_SIZE 1024
//#define PROCF_NAME "nf_ids"

static struct proc_dir_entry *fw_proc_file;

//unsigned long procf_buffer_pos;
//char *procf_buffer;

//static struct fw_rule policy_list;

//struct net_device *eth0=(const struct net_device *)dev_get_by_name(&init_net, "eth0");
//struct net_device *eth1=(const struct net_device *)dev_get_by_name(&init_net, "eth1");

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

unsigned int hook_func_in(unsigned int hooknum,
                       struct sk_buff *skb,            //originally **skb
                       struct net_device *in,
                       struct net_device *out,
                       int (*okfn)(struct sk_buff *))
        {
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;
        struct udphdr *udp_header;
        ip_header = (struct iphdr *)skb_network_header(skb);
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        udp_header = (struct udphdr *)skb_transport_header(skb);
        unsigned int src_ip = (unsigned int)ip_header->saddr;
        unsigned int dst_ip = (unsigned int)ip_header->daddr;
        unsigned int src_port = 0;
        unsigned int dst_port = 0;
        struct list_head *p;
        struct fw_rule *a_rule;
        int i=0;
        unsigned char *prot;
	switch(ip_header->protocol)
			{
			case 1:
				prot = "ICMP";
				break;
			case 6:
        prot =	"TCP";
				src_port = (unsigned int)ntohs(tcp_header->source);
				dst_port = (unsigned int)ntohs(tcp_header->dest);
				break;
			case 17:
        prot =	"UDP";
				src_port = (unsigned int)ntohs(udp_header->source);
        dst_port = (unsigned int)ntohs(udp_header->dest);
				break;
			default:
				prot = "OTHER";
			}

        printk(KERN_INFO "IN: %s packet from %pI4 to %pI4. Sport: %d Dport: %d",
                prot, &src_ip, &dst_ip, src_port, dst_port);

	list_for_each(p, &policy_list.list)
                {
                i++;
                a_rule = list_entry(p, struct fw_rule, list);
                if(a_rule->in_out != 1)
                        {
                        printk(KERN_INFO "Rule %d (a_rule->in_out:%u) did not match IN packet, rule doesn't specify as IN.\n",
                                                i, a_rule->in_out);
                        continue;
                        }
                else
                    	{
                        if((a_rule->proto==1) && (ip_header->protocol != 6))
                                {
                                printk(KERN_INFO "Rule %d not match: Rule-TCP, Packet->Not TCP\n", i);
                                continue;
                                }
                        else if((a_rule->proto==2) && (ip_header->protocol != 17))
                                {
                                printk(KERN_INFO "Rule %d not match: Rule-UDP, Packet->Not UDP\n", i);
                                continue;
                                }
                	if(a_rule->src_ip==0)
                       		{
                        	printk(KERN_INFO "NO src_ip specified");
                        	}
                	else
                    		{
                        	if(!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask))
                                	{
                                	printk(KERN_INFO "Rule %d : src_ip MISMATCH\n", i);
                                	continue;
                                	}
                        	}
                	if(a_rule->dst_ip == 0)
                        	{
                        	printk(KERN_INFO "NO dst_ip specified");
                        	}
                	else
                    		{
                        	if(!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask))
                                	{
                                	printk(KERN_INFO "Rule %d: dst_ip MISMATCH\n", i);
                                	continue;
                                	}
                        	}
			if(a_rule->src_port==0)
                        	{
                        	printk(KERN_INFO "NO src_port specified");
                        	}
                	else if(src_port!=a_rule->src_port)
                	        {
                	        printk(KERN_INFO "Rule %d: src_port MISMATCH\n", i);
                	        continue;
                        	}
                	if(a_rule->dst_port == 0)
                        	{
                        	printk(KERN_INFO "NO dst_port specified");
                        	}
                	else if(dst_port!=a_rule->dst_port)
                        	{
                        	printk(KERN_INFO "Rule %d: dst_port MISMATCH\n", i);
                        	continue;
                        	}

			if (a_rule->action==0)                          //if match found
                        	{
                        	printk(KERN_INFO "A match is found: %d, DROPPING the packet.\n", i);
                        	printk(KERN_INFO "---------------------------------------\n");
                        	return NF_DROP;
                        	}
                	else
                    		{
                        	printk(KERN_INFO "A match is found: %d, ACCEPTING the packet.\n", i);
                        	printk(KERN_INFO "---------------------------------------\n");
                        	return NF_ACCEPT;
                        	}
			}
		}
		printk(KERN_INFO "No matches found, ACCEPTING the packet\n");
                printk(KERN_INFO "--------------------------------------\n");
                return NF_ACCEPT;
	}

unsigned int hook_func_out(unsigned int hooknum,
                       struct sk_buff *skb,            //originally **skb
                       struct net_device *in,
                       struct net_device *out,
                       int (*okfn)(struct sk_buff *))
	{
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;
        struct udphdr *udp_header;
        ip_header = (struct iphdr *)skb_network_header(skb);
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        udp_header = (struct udphdr *)skb_transport_header(skb);
        unsigned int src_ip = (unsigned int)ip_header->saddr;
        unsigned int dst_ip = (unsigned int)ip_header->daddr;
        unsigned int src_port = 0;
        unsigned int dst_port = 0;
        struct list_head *p;
        struct fw_rule *a_rule;
	//char src_ip_str[16], dst_ip_str[16];    //////////////////////////////////////////
        int i = 0;
        unsigned char *prot;

	/*
	printk(KERN_INFO "skb->dev->name:%s && out->name:%s\n", skb->dev->name, out->name);
	struct net_device *eth0;
	//eth0 = (struct net_device *)kmalloc(sizeof(eth0), GFP_NOWAIT);
	eth0=(struct net_device *)dev_get_by_name(&init_net, "eth0");
	struct net_device *eth1;
	//eth1 = (struct net_device *)kmalloc(sizeof(eth1), GFP_NOWAIT);
	eth1=(struct net_device *)dev_get_by_name(&init_net, "eth1");
	printk(KERN_INFO "eth0->name:%s && eth1->name:%s", eth0->name, eth1->name);
	*/

	//swap_intfc(skb->dev, out);
  //swap_intfc(&skb->dev, &out)

  printk(KERN_INFO "skb->dev->name:%s && out->name:%s\n", skb->dev->name, out->name);

	switch(ip_header->protocol)
                        {
                        case 1:
                                prot = "ICMP";
                                break;
                        case 6:
                                prot =  "TCP";
                                src_port = (unsigned int)ntohs(tcp_header->source);
                                dst_port = (unsigned int)ntohs(tcp_header->dest);
                                break;
                        case 17:
                                prot =  "UDP";
                                src_port = (unsigned int)ntohs(udp_header->source);
                                dst_port = (unsigned int)ntohs(udp_header->dest);
                                break;
                        default:
                                prot = "OTHER";
                        }

	list_for_each(p, &policy_list.list)
                {
                i++;
                a_rule = list_entry(p, struct fw_rule, list);
                if (a_rule->in_out != 2)
                        {
                        printk(KERN_INFO "Rule %d (a_rule->in_out:%u) did not match OUT packet, rule doesn't specify as OUT.\n", i, a_rule->in_out);
                        continue;
                        }
                else
                    	{
                        if((a_rule->proto==1) && (ip_header->protocol != 6))      //TCP
                                {
                                printk(KERN_INFO "Rule %d not match: Rule-TCP, Packet->Not TCP\n", i);
                                continue;
                                }
                        else if((a_rule->proto==2) && (ip_header->protocol != 17))    //UDP
                                {
                                printk(KERN_INFO "Rule %d not match: Rule-UDP, Packet->Not UDP\n", i);
                                continue;
                                }
			if (a_rule->src_ip==0)
                        	{
                        	printk(KERN_INFO "NO src_ip specified");
                        	}
                	else
                        	{
                        	if(!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask))
                        	        {
                        	        printk(KERN_INFO "Rule %d: src_ip MISMATCH\n", i);
                        	        continue;
                        	        }
                        	}
               		if (a_rule->dst_ip == 0)
                        	{
                        	printk(KERN_INFO "NO dst_ip specified");
                        	}
                	else
                    		{
                        	if(!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask))
                        	        {
                        	        printk(KERN_INFO "Rule %d: dst_ip MISMATCH\n", i);
                        	        continue;
                                	}
                        	}
			if(a_rule->src_port==0)
                	        {
                	        printk(KERN_INFO "NO src_port specified");
                	        }
                	else if(src_port!=a_rule->src_port)
                	        {
                       		printk(KERN_INFO "Rule %d: src_port MISMATCH\n", i);
                        	continue;
                        	}
                	if(a_rule->dst_port == 0)
                        	{
                        	printk(KERN_INFO "NO dst_port specified");
                        	}
                	else if(dst_port!=a_rule->dst_port)
                	        {
                        	printk(KERN_INFO "Rule %d: dst_port MISMATCH\n", i);
                        	continue;
                        	}
			if (a_rule->action==0)  		                        //if match found
                        	{
                        	printk(KERN_INFO "A match is found: %d, DROPPING the packet.\n", i);
                        	printk(KERN_INFO "---------------------------------------\n");
                        	return NF_DROP;
                        	}
                	else
                    		{
                        	printk(KERN_INFO "A match is found: %d, ACCEPTING the packet.\n", i);
                        	printk(KERN_INFO "---------------------------------------\n");
                        	return NF_ACCEPT;
                        	}
			}
		}
	printk(KERN_INFO "No matching is found, accept the packetn");
   	printk(KERN_INFO "---------------------------------------n");
   	return NF_ACCEPT;
	}

int init_module()
        {
	printk(KERN_INFO "Kernel module Flarewall Loaded.\n");
        INIT_LIST_HEAD(&(policy_list.list));
	procf_buffer = (char *) vmalloc(PROCF_MAX_SIZE);
	fw_proc_file = create_proc_entry(PROCF_NAME, 0644, NULL);
    	if (fw_proc_file==NULL)
		{
        	printk(KERN_INFO "Error: could not initialize /proc/%sn", PROCF_NAME);
        	return -ENOMEM;
    		}
	fw_proc_file->read_proc = procf_read;
    	fw_proc_file->write_proc = procf_write;
	printk(KERN_INFO "/proc/%s is createdn", PROCF_NAME);

        /* Fill in the hook structure for incoming packet hook*/
        nfho.hook = hook_func_in;
        nfho.hooknum = NF_INET_PRE_ROUTING;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;
        nf_register_hook(&nfho);         // Register the hook

        /* Fill in the hook structure for outgoing packet hook*/
        nfho_out.hook = hook_func_out;
        nfho_out.hooknum = NF_INET_POST_ROUTING;
        nfho_out.pf = PF_INET;
        nfho_out.priority = NF_IP_PRI_FIRST;
        nf_register_hook(&nfho_out);    // Register the hook

	//For testing purpose
        //add_a_test_rule();

        //- start of nat_standalone integration
        nf_nat_standalone_init();

        return 0;
        }

void cleanup_module()
        {
	struct list_head *p, *q;
        struct fw_rule *a_rule;
        nf_unregister_hook(&nfho);
        nf_unregister_hook(&nfho_out);
        printk(KERN_INFO "Free policy lists\n");

  //- start of nat_standalone integration
  nf_nat_standalone_fini();


	list_for_each_safe(p, q, &policy_list.list)
                {
                printk(KERN_INFO "Free one.\n");
                a_rule = list_entry(p, struct fw_rule, list);
                list_del(p);
                kfree(a_rule);
                }
	remove_proc_entry(PROCF_NAME, NULL);
	printk(KERN_INFO "Flarewall module unloaded.\n");
	}
