#!/bin/sh
## Firewall para AlimaticPR
## Ing. Jelvys Triana Castro
## =================================
## Res Dominio alimaticpr.alinet.cu
## =================================
## Última Actualización: 2024.03.19
## 
## clear
echo
echo -n Van las reglas de Firewall...
echo

## FLUSH de reglas
iptables -F
iptables -X
iptables -Z
iptables -t nat -F

## Establecemos politica por defecto
iptables -P INPUT  ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Con esto permitimos hacer forward de paquetes en el firewall, o sea
# que otras maquinas puedan salir a traves del firewall.
iptables -A INPUT -s 0/0 -p tcp --dport 80 -j ACCEPT

# Permitimos el acceso a CPUs que la hagan de servidor Web
# Acepto conexiones al puerto 80 HTTP de las siguientes IPs
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.2:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.3:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.5:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.6:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.7:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.8:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.9:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to 192.168.1.1:80

# Acepto conexiones al puerto 21 FTP de las siguientes IPs
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 21 -j DNAT --to 192.168.1.14:21

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -A INPUT -i lo -j ACCEPT

# Al firewall tenemos acceso desde la red local (Solo desde la Red 253)
iptables -A INPUT -s 192.168.0.0/24 -i ens18 -j ACCEPT

# Puertos 80 redirigimos al 3128 del squid
iptables -t nat -A PREROUTING -s 192.168.0.0/24 -i ens18 -p tcp --dport 80 -j REDIRECT --to-port 3128

#ICMP
iptables -A INPUT -i ens18 -p icmp -j ACCEPT
iptables -A OUTPUT -o ens18 -p icmp -j ACCEPT 

iptables -A FORWARD -i ens18 -p icmp -j ACCEPT
iptables -A FORWARD -o ens18 -p icmp -j ACCEPT

# Acceso a FTP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 20:21 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 20:21 -j ACCEPT

# Acceso a SSH
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 22 -j ACCEPT

# Aceptamos que consulten los DNS
#############################################################################
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 53 -j ACCEPT

iptables -t nat -A PREROUTING -s 192.168.0.0/24 -i ens18 -p tcp --dport 1863 -j REDIRECT --to-port 3128

############################
# Bloqueamos programas P2P #
############################
# eMule
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 4661:4670 -j DROP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 4661:4670 -j DROP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 5662 -j DROP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 5662 -j DROP

# BitTorrent
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 6881:6999 -j DROP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 6881:6999 -j DROP

# Ares, Limewire, eDonkey, uTorrent
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 5001:5004 -j DROP
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 5001:5004 -j DROP

#########################################
# Permitimos acceso a programas comunes #
#########################################

# Acceso a Yahoo Messenger
#############################################################################
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 5050 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 5050 -j ACCEPT

# Acceso a SSL
##############################################################################
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 443 -j ACCEPT

# Acceso a VoIP
##############################################################################
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 4569 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 4569 -j ACCEPT

#################
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 5060 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 5060 -j ACCEPT

#Compranet
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 8000:8010 -j ACCEPT

#Puerto de administracion Webmin
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 10111 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 10111 -j ACCEPT

iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 10000 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 10000 -j ACCEPT

#Puerto de adicionales 
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 8443 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 8443 -j ACCEPT

iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p tcp --dport 8081 -j ACCEPT
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -p udp --dport 8081 -j ACCEPT

# Y denegamos el resto. Si se necesita alguno, ya avisaran... :p
iptables -A FORWARD -s 192.168.0.0/24 -i ens18 -j DROP

# Ahora hacemos enmascaramiento de la red local
# y activamos el BIT DE FORWARDING 
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o ens18 -j MASQUERADE

echo ""
echo "Listo, verifica lo que se aplica con el comando:"
echo ""
echo "         iptables -L -n"
echo ""
echo "Dudas, comentarios o sugerencias, enviar un e-mail a:"
echo "jelvys.triana@alimatic.cu"
echo ""
echo "¡Que tengas un buen día!"
echo ""

# Fin del script
