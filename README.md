# Host-scanner
This is my host scanner tool that gives you awake hosts in the network or you can use it against one ip address if you want to check it is awake or not.
Scanner uses 4 protocol to scan network:

1.ARP - If you are scanning your local network , this option is the best because it is faster. You can use this option with -a argument

2.ICMP ping-This scan sendes ping request to ip address. you can use this option with -p

3.TCP connect-This option uses tcp protocol thats why it needs port too.But if you dont give any port it will use default(80,443).You can use this option with -t

4.UDP-With TCP scan you scan only services uses TCP protcol if there is a service that uses UDP protocol you will not see it.It is better to check both protocols.You can use this option with -u

I explain scanner simple here.But there is detailed explanation in this article I posted at medium you can check it if you are curious about learning how this code works.And you can create your own scanner.
