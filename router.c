#include <arpa/inet.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "include/lib.h"
#include "include/protocols.h"



/* Tabela de rutare */
struct route_table_entry *rtable;
int rtable_len;

/* Tabela ARP */
struct arp_table_entry *arp_table;
int arp_table_len;



/* Functie compare crescatoare pentru qsort */
int compare(const void *entry, const void *other_entry) {

    const struct route_table_entry *in1 = (const struct route_table_entry *)entry;
    const struct route_table_entry *in2 = (const struct route_table_entry *)other_entry;

    uint32_t in1_mask = ntohl(in1->mask);
    uint32_t in2_mask = ntohl(in2->mask);
    uint32_t in1_prefix = ntohl(in1->prefix);
    uint32_t in2_prefix = ntohl(in2->prefix);

    // Comparam mastile
    if (in1_mask < in2_mask) {
        return -1;
    } else if (in1_mask > in2_mask) {
        return 1;
    }

    // Daca mastile sunt egale, comparam prefixele
    if (in1_prefix < in2_prefix) {
        return -1;
    } else if (in1_prefix > in2_prefix) {
        return 1;
    }

    return 0;
}


/* Funcie ce sorteaza tabela de rutrare */
void sort_route_table(struct route_table_entry *rtable, int rtable_size) {
    qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare);
}




/*
  Functie care cauta cea mai buna ruta pentru o adresa IP cu destinatia data si
  returneaza un pointer catre intrarea aferenta din tabela de rutare / NULL daca
  nu am gasit nicio ruta, functie optimizata folosind cautarea binara
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    int index = -1;
    int left = 0, right = rtable_len - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        uint32_t ip_w_mask = rtable[mid].mask & ip_dest;

        if (rtable[mid].prefix == ip_w_mask) {
            // Actualizam index daca masca curenta este mai specifica decat cea gasita anterior
            if (index == -1 || ntohl(rtable[index].mask) < ntohl(rtable[mid].mask)) {
                index = mid;
            }
            left = mid + 1;
        } else if (ntohl(ip_w_mask) > ntohl(rtable[mid].prefix)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return (index == -1) ? NULL : &rtable[index];
}




/*
  Functie ce cauta o intrare in tabela ARP pentru o adresă IP data si
  returneaza un pointer la intrarea corespunzatoare /  NULL daca nu exista
  (functie implementata in lab4)
*/
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_table_len; i++)
        if (arp_table[i].ip == given_ip)
            return &arp_table[i];

    return NULL;
}




int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    init(argc - 2, argv + 2);

	// Alocam memorie pentru tabele si le citim din fisiere
    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(rtable == NULL, "memory");
    arp_table = malloc(sizeof(struct  arp_table_entry) * 100000);
    DIE(arp_table == NULL, "memory");

    rtable_len = read_rtable(argv[1], rtable);
    arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	// Sortam tabela de rutare pentru optimizarea cautarii
	sort_route_table(rtable, rtable_len);

    while (1) {
        int interface;
        size_t len;

        // Primim pachetul
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

		// Extragem headerul frameului Ethernet si headerul IP
		struct ether_header *ether_header;
		struct iphdr *ip_header;
		char *tmp_buf = buf;
		ether_header = (struct ether_header *) tmp_buf;
		tmp_buf += sizeof(struct ether_header);
		ip_header = (struct iphdr *) tmp_buf;

        // Verificam ca tipul pachetului sa fie doar IPv4
        if (ether_header->ether_type != ntohs(0x0800)) {
            printf("Ignored non-IPv4 packet\n");
            continue;
        }

        // Verificam checksumul pentru a ne asigura integritatea headerului IP
		uint16_t received_sum = ntohs(ip_header->check);
		ip_header->check = 0;
		if (checksum((uint16_t *) ip_header, sizeof(struct iphdr)) != received_sum) {
    		printf("Ignored packet; checksum failed\n");
    		continue;
		}

        // Gasim cea mai optima ruta pentru a ajunge la destinatie 
        struct route_table_entry *next_rte = get_best_route(ip_header->daddr);
        if (!next_rte) {
            printf("Ignored packet; route not found\n"); 
            continue;
        }

        // Verificam dacă TTL este valid sau nu
		if (ip_header->ttl < 1) {
    		printf("Ignored packet; no more ttl\n");
    		continue;
		}

		// Daca TTL este inca valid, il decrementam si actualizam checksumul
		ip_header->ttl--;
		uint16_t new_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
		ip_header->check = 0;
		ip_header->check = htons(new_checksum);


        // Cautam intrarea ARP pentru urmatorul hop
		struct arp_table_entry *next_arpe;
		unsigned char *destination_mac;
		next_arpe = get_arp_entry(next_rte->next_hop);
		if (next_arpe == NULL) {
    		printf("Ignored packet; no MAC found\n");
    		continue;
		}

		destination_mac = next_arpe->mac;
		memcpy(ether_header->ether_dhost, destination_mac, 6);


        // Trimitem pachetul
        send_to_link(next_rte->interface, buf, len);
    }
}


