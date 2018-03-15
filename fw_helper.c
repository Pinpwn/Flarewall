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
#include "net/ipv4/netfilter/ip_nat_standalone.c"

/****************************************************/
MODULE_LICENSE("GPL v3.0");

MODULE_DESCRIPTION("Flarewall");

MODULE_AUTHOR("Kushagra Choudhary/Pinpwn");
/****************************************************/

#define PROCF_MAX_SIZE 1024
#define PROCF_NAME "flarewall"

struct fw_rule_desc                     //struct for fw policy
        {
	unsigned char		in_out;
        char      *src_ip;
        char  		*src_netmask;
        char 			*src_port;
        char 			*dst_ip;
        char 			*dst_netmask;
        char 			*dst_port;
        unsigned char 		proto;
        unsigned char 		action;
        };

struct fw_rule
	     {
	      unsigned char 		in_out;           //0: neither in nor out, 1: in, 2: out
        unsigned int 		src_ip;
        unsigned int 		src_netmask;
        unsigned int 		src_port;          //0 to 2^32
        unsigned int 		dst_ip;
        unsigned int 		dst_netmask;
        unsigned int 		dst_port;
        unsigned char 		proto;            //0: all, 1: tcp, 2: udp
        unsigned char 		action;           //0: for block, 1: for unblock
        struct list_head 	list;
       };

void init_fw_rule_desc(struct fw_rule_desc* a_rule_desc)
	{
    	a_rule_desc->in_out       = 0;
    	a_rule_desc->src_ip       = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->src_netmask  = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->src_port     = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->dst_ip      = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->dst_netmask = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->dst_port    = (char *)kmalloc(16, GFP_KERNEL);
    	a_rule_desc->proto        = 0;
   	a_rule_desc->action 	  = 0;
	}

unsigned long procf_buffer_pos;
char *procf_buffer;

static struct fw_rule policy_list;

unsigned int port_str_to_int(char *port_str)
        {
	unsigned int port = 0;
        int i = 0;
        if (port_str==NULL)
                {
                return 0;
                }
        while (port_str[i]!='\0')
                {
                port = port*10 + (port_str[i]-'0');
                ++i;
                }
        return port;
        }

void port_int_to_str(unsigned int port, char *port_str)
	{
    	sprintf(port_str, "%u", port);
	}

unsigned int ip_str_to_hl(char *ip_str) //from "192.168.1.168" to [192][168][1][168]
        {
	unsigned char ip_array[4];
        int i = 0;
        unsigned int ip = 0;
        if (ip_str==NULL)
                {
                return 0;
                }
        memset(ip_array, 0, 4);
        while (ip_str[i]!='.')
                {
                ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
                }
        ++i;
	while (ip_str[i]!='.')
                {
                ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
                }
        ++i;
	while (ip_str[i]!='.')
                {
                ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
                }
        ++i;
	while (ip_str[i]!='\0')
                {
                ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
                }
        /*convert from byte array to host long integer format*/
        ip = (ip_array[0] << 24);
        ip = (ip | (ip_array[1] << 16));
        ip = (ip | (ip_array[2] << 8));
        ip = (ip | ip_array[3]);
        //printk(KERN_INFO "ip_str_to_hl convert %s to %un", ip_str, ip);
        return ip;
        }

void ip_hl_to_str(unsigned int ip, char *ip_str)
	{
    	/*convert hl to byte array first*/
    	unsigned char ip_array[4];
    	memset(ip_array, 0, 4);
    	ip_array[0] = (ip_array[0] | (ip >> 24));
    	ip_array[1] = (ip_array[1] | (ip >> 16));
    	ip_array[2] = (ip_array[2] | (ip >> 8));
    	ip_array[3] = (ip_array[3] | ip);
    	sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
	}

bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask)
	{
    	unsigned int tmp = ntohl(ip);    //network to host long
    	int cmp_len = 32;
    	int i = 0, j = 0;
    	printk(KERN_INFO "compare ip: %u <=> %un", tmp, ip_rule);
   	if (mask != 0)
		{
       		//printk(KERN_INFO "deal with maskn");
       		//printk(KERN_INFO "mask: %d.%d.%d.%dn", mask[0], mask[1], mask[2], mask[3]);
       		cmp_len = 0;
       		for (i = 0; i < 32; ++i)
			{
      			if (mask & (1 << (32-1-i)))
         			cmp_len++;
      			else
         			break;
       			}
    		}
    					//compare the two IP addresses for the first cmp_len bits
    	for (i = 31, j = 0; j < cmp_len; --i, ++j)
		{
       		if ((tmp & (1 << i)) != (ip_rule & (1 << i)))
			{
            		printk(KERN_INFO "ip compare: %d bit doesn't matchn", (32-i));
            		return false;
        		}
    		}
    	return true;
	}

void add_fw_rule(struct fw_rule_desc* a_rule_desc)
	{
    	struct fw_rule* a_rule;
    	a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    	if (a_rule == NULL)
		{
        	printk(KERN_INFO "error: cannot allocate memory for a_new_rulen");
        	return;
    		}
    	a_rule->in_out = a_rule_desc->in_out;
    	if (strcmp(a_rule_desc->src_ip, "-") != 0)
        	a_rule->src_ip = ip_str_to_hl(a_rule_desc->src_ip);
    	else
        	a_rule->src_ip = NULL;
    	if (strcmp(a_rule_desc->src_netmask, "-") != 0)
        	a_rule->src_netmask = ip_str_to_hl(a_rule_desc->src_netmask);
    	else
        	a_rule->src_netmask = NULL;
    	if (strcmp(a_rule_desc->src_port, "-") != 0)
        	a_rule->src_port = port_str_to_int(a_rule_desc->src_port);
    	else
       		a_rule->src_port = NULL;
    	if (strcmp(a_rule_desc->dst_ip, "-") != 0)
        	a_rule->dst_ip = ip_str_to_hl(a_rule_desc->dst_ip);
    	else
        	a_rule->dst_ip = NULL;
    	if (strcmp(a_rule_desc->dst_netmask, "-") != 0)
        	a_rule->dst_netmask = ip_str_to_hl(a_rule_desc->dst_netmask);
    	else
        	a_rule->dst_netmask = NULL;
    	if (strcmp(a_rule_desc->dst_port, "-") != 0)
        	a_rule->dst_port = port_str_to_int(a_rule_desc->dst_port);
    	else
        	a_rule->dst_port = NULL;
    	a_rule->proto = a_rule_desc->proto;
    	a_rule->action = a_rule_desc->action;
    	printk(KERN_INFO "add_fw_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, dst_ip=%u, dst_netmask=%u, dst_port=%u, proto=%u, action=%un", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask, a_rule->dst_port, a_rule->proto, a_rule->action);
    	INIT_LIST_HEAD(&(a_rule->list));
    	list_add_tail(&(a_rule->list), &(policy_list.list));
	}

void delete_a_rule(int num)
        {
	int i = 0;
        struct list_head *p, *q;
        struct fw_rule *a_rule;
        printk(KERN_INFO "delete a rule: %d\n", num);
        list_for_each_safe(p, q, &policy_list.list)
                {
                ++i;
                if (i == num)
                        {
                        a_rule = list_entry(p, struct fw_rule, list);
                        list_del(p);
                        kfree(a_rule);
                        return;
                        }
                }
        }

int procf_read(char *buffer, char **buffer_location,
	       off_t offset, int buffer_length, int *eof,
	       void *data)
	{
	    int ret;
	    struct fw_rule *a_rule;
	    char token[20];
	    printk(KERN_INFO "procf_read (/proc/%s) called n", PROCF_NAME);
	    if (offset > 0)
		{
	        printk(KERN_INFO "eof is 1, nothing to readn");
	        *eof = 1;
	        return 0;
		}
	    else
		{
        	procf_buffer_pos = 0;
        	ret = 0;
        	list_for_each_entry(a_rule, &policy_list.list, list) {
            	//in or out
            	if (a_rule->in_out==1)
			{
            	    	strcpy(token, "in");
            		}
		else if (a_rule->in_out==2)
			{
            	    	strcpy(token, "out");
            		}
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//src ip
            	if (a_rule->src_ip == NULL)
			{
                	strcpy(token, "-");
            		}
		else
			{
	                ip_hl_to_str(a_rule->src_ip, token);
        	        }
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//src netmask
            	if (a_rule->src_netmask==NULL)
			{
                	strcpy(token, "-");
            		}
		else
			{
                	ip_hl_to_str(a_rule->src_netmask, token);
            		}
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
           	//src port
            	if (a_rule->src_port==0)
			{
                	strcpy(token, "-");
            		}
		else
			{
	                port_int_to_str(a_rule->src_port, token);
	                }
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//dst ip
            	if (a_rule->dst_ip==NULL)
			{
            	    	strcpy(token, "-");
            		}
		else
			{
                	ip_hl_to_str(a_rule->dst_ip, token);
	            	}
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//dst netmask
            	if (a_rule->dst_netmask==NULL) {
                	strcpy(token, "-");
            		}
		else
			{
                	ip_hl_to_str(a_rule->dst_netmask, token);
	         	}
		printk(KERN_INFO "token: %sn", token);
                memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
                procf_buffer_pos += strlen(token);
                memcpy(procf_buffer + procf_buffer_pos, " ", 1);
                procf_buffer_pos++;
               //dst port
 	        if (a_rule->dst_port==0)
			{
        	        strcpy(token, "-");
        	    	}
		else
			{
                	port_int_to_str(a_rule->dst_port, token);
            		}
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//protocol
            	if (a_rule->proto==0)
			{
           	     	strcpy(token, "ALL");
           	 	}
		else if (a_rule->proto==1)
			{
           	     	strcpy(token, "TCP");
          	  	}
		else if (a_rule->proto==2)
			{
                	strcpy(token, "UDP");
            		}
            	printk(KERN_INFO "token: %sn", token);
            	memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            	procf_buffer_pos += strlen(token);
            	memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            	procf_buffer_pos++;
            	//action
            if (a_rule->action==0) {
                strcpy(token, "BLOCK");
            } else if (a_rule->action==1) {
                strcpy(token, "UNBLOCK");
            }
            printk(KERN_INFO "token: %sn", token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, "n", 1);
            procf_buffer_pos++;
        }
        //copy from procf_buffer to buffer
        printk(KERN_INFO "procf_buffer_pos: %ldn", procf_buffer_pos);
        memcpy(buffer, procf_buffer, procf_buffer_pos);
        ret = procf_buffer_pos;
    }
    return ret;
}

int procf_write(struct file *file, const char *buffer, unsigned long count, void *data)
	{
   	int i, j;
   	struct fw_rule_desc *rule_desc;
   	printk(KERN_INFO "procf_write is called.n");
   	/*read the write content into the storage buffer*/
   	procf_buffer_pos = 0;
   	printk(KERN_INFO "pos: %ld; count: %ldn", procf_buffer_pos, count);
   	if (procf_buffer_pos + count > PROCF_MAX_SIZE)
		{
   	    	count = PROCF_MAX_SIZE-procf_buffer_pos;
   		}
   	if (copy_from_user(procf_buffer+procf_buffer_pos, buffer, count))
		{
 	      	return -EFAULT;
	  	}
   	if (procf_buffer[procf_buffer_pos] == 'p')
		{
       		//print command
       		return 0;
   		}
	else if (procf_buffer[procf_buffer_pos] == 'd')
		{
       		//delete command
       		i = procf_buffer_pos+1; j = 0;
       		while ((procf_buffer[i]!=' ') && (procf_buffer[i]!='n'))
			{
           		printk(KERN_INFO "delete: %dn", procf_buffer[i]-'0');
           		j = j*10 + (procf_buffer[i]-'0');
           		++i;
       			}
       		printk(KERN_INFO "delete a rule: %dn", j);
       		delete_a_rule(j);
       		return count;
   		}
   		/*add a new policy according to content int the storage buffer*/
   	rule_desc = kmalloc(sizeof(*rule_desc), GFP_KERNEL);
   	if (rule_desc == NULL)
		{
   		printk(KERN_INFO "error: cannot allocate memory for rule_descn");
       		return -ENOMEM;
   		}
   	init_fw_rule_desc(rule_desc);
   	/**fill in the content of the new policy **/
   	/***in_out***/
   	i = procf_buffer_pos; j = 0;
   	if (procf_buffer[i]!=' ')
		{
   	    	rule_desc->in_out = (unsigned char)(procf_buffer[i++] - '0');
   		}
   	++i;
   	printk(KERN_INFO "in or out: %un", rule_desc->in_out);
   	/***src ip***/
   	j = 0;
   	while (procf_buffer[i]!=' ')
		{
   	    	rule_desc->src_ip[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->src_ip[j] = '\0';
   	printk(KERN_INFO "src ip: %sn", rule_desc->src_ip);
   	/***src netmask***/
   	j = 0;
   	while (procf_buffer[i]!=' ')
		{
   	    	rule_desc->src_netmask[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->src_netmask[j] = '\0';
   	printk(KERN_INFO "src netmask: %sn", rule_desc->src_netmask);
   	/***src port number***/
   	j = 0;
   	while (procf_buffer[i]!=' ')
		{
       		rule_desc->src_port[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->src_port[j] = '\0';
   	printk(KERN_INFO "src_port: %sn", rule_desc->src_port);
   	/***dst ip***/
   	j = 0;
  	while (procf_buffer[i]!=' ')
		{
       		rule_desc->dst_ip[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->dst_ip[j] = '\0';
   	printk(KERN_INFO "dst ip: %sn", rule_desc->dst_ip);
   	/***dst netmask***/
   	j = 0;
   	while (procf_buffer[i]!=' ')
		{
   	    	rule_desc->dst_netmask[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->dst_netmask[j] = '\0';
   	printk(KERN_INFO "dst netmask%sn", rule_desc->dst_netmask);
   	/***dst port***/
   	j = 0;
   	while (procf_buffer[i]!=' ')
		{
       		rule_desc->dst_port[j++] = procf_buffer[i++];
   		}
   	++i;
   	rule_desc->dst_port[j] = '\0';
   	printk(KERN_INFO "dst port: %sn", rule_desc->dst_port);
   	/***proto***/
   	j = 0;
   	if (procf_buffer[i]!=' ')
		{
  	     	if (procf_buffer[i] != '-')
           		rule_desc->proto = (unsigned char)(procf_buffer[i++]-'0');
       		else
           		++i;
   		}
   	++i;
   	printk(KERN_INFO "proto: %dn", rule_desc->proto);
   	/***action***/
   	j = 0;
   	if (procf_buffer[i]!=' ')
		{
       		if (procf_buffer[i] != '-')
           		rule_desc->action = (unsigned char)(procf_buffer[i++]-'0');
       		else
           		++i;
   		}
   	++i;
   	printk(KERN_INFO "action: %dn", rule_desc->action);
   	add_fw_rule(rule_desc);
   	kfree(rule_desc);
   	printk(KERN_INFO "--------------------n");
   	return count;
	}

  //const struct net_device *eth0=dev_get_by_name(&init_net, "eth0");
  //const struct net_device *eth1 = dev_get_by_name(&init_net, "eth1");

  /*
  void swap_intfc(struct net_device *dev, const struct net_device *out)
  	{
          //const struct net_device *eth0=(const struct net_device *)dev_get_by_name(&init_net, "eth0");
  	struct net_device *eth0=dev_get_by_name(&init_net, "eth0");
  	if(eth0==0)
  		printk(KERN_INFO "eth0 NOT SET!\n");
  	else
  		printk(KERN_INFO "eth0 set!\n");
  	//const struct net_device *eth1 = (const struct net_device *)dev_get_by_name(&init_net, "eth1");
  	struct net_device *eth1=dev_get_by_name(&init_net, "eth1");
  	if(eth1==0)
  		printk(KERN_INFO "eth1 NOT SET!\n");
  	else
  		printk(KERN_INFO "eth1 set!\n");
  	if(!strcmp(out->name, "eth0"))
  	//if(strcmp(out->name, "eth0")==0)
  		{
  		dev=eth1;
  		//out=eth1;
  		printk(KERN_INFO "------swapped netdev : out : eth0->eth1------\n");
  		}
  	else if(!strcmp(out->name, "eth1"))
  	//else if(strcmp(out->name, "eth1")==0)
  		{
  		dev=eth0;
  		//out=eth0;
  		printk(KERN_INFO "------swapped netdev : out : eth1->eth0------\n");
  		}
  	else
  		printk(KERN_INFO "GAZAB HO GYA!\n");
  	}
  */
/**
  void swap_intfc(struct net_device *dev, struct net_device *out)
          {
  	printk(KERN_INFO "dev->name:%s && out->name:%s\n", dev->name, out->name);
  	struct net_device *eth0;
  	eth0 = (struct net_device *)kmalloc(sizeof(eth0), GFP_NOWAIT);
  	eth0=(struct net_device *)dev_get_by_name(&init_net, "eth0");
          struct net_device *eth1;
  	eth1 = (struct net_device *)kmalloc(sizeof(eth1), GFP_NOWAIT);
  	eth1=(struct net_device *)dev_get_by_name(&init_net, "eth1");
          printk(KERN_INFO "eth0->name:%s && eth1->name:%s", eth0->name, eth1->name);

          //const struct net_device *eth0=(const struct net_device *)dev_get_by_name(&init_net, "eth0");
          //struct net_device *eth0=dev_get_by_name(&init_net, "eth0");
          if(!eth0)
                  printk(KERN_INFO "eth0 NOT SET!\n");
          else
                  printk(KERN_INFO "eth0 set!\n");
          //const struct net_device *eth1 = (const struct net_device *)dev_get_by_name(&init_net, "eth1");
          //struct net_device *eth1=dev_get_by_name(&init_net, "eth1");
          if(!eth1)
                  printk(KERN_INFO "eth1 NOT SET!\n");
          else
                  printk(KERN_INFO "eth1 set!\n");

  	char intfc0[IFNAMSIZ]="eth0";
  	char intfc1[IFNAMSIZ]="eth1";

          if(strcmp(out->name, intfc0)==0)
          //if(strcmp(out->name, "eth0")==0)
          //if(out==eth0)
                  {
                  dev=eth1;
                  //memcpy(dev, eth1, sizeof(struct net_device)); !!!!!DO NOT USE !!!
  		//out=eth1;
                  printk(KERN_INFO "------swapped netdev : out : eth0->eth1------\n");
                  }
          //else if(out==eth1)
          //else if(strcmp(out->name, "eth1")==0)
  	else if(strcmp(out->name, intfc1)==0)
                  {
                  dev=eth0;
  		//memcpy(dev, eth0, sizeof(struct net_device)); !!! DO NOT USE !!!
                  //out=eth0;
                  printk(KERN_INFO "------swapped netdev : out : eth1->eth0------\n");
                  }
          else
                  printk(KERN_INFO "GAZAB HO GYA!\n");
          }
**/
