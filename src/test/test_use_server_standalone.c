#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h> // For isalnum, tolower in helpers

#define DNSNAMEBUFSIZE 256
#define C_INCLUDED 1
#define C_EXCLUDED 2
#define C_SIMPLE_ONLY 3
#define C_FQDN_ONLY 4

// --- Minimal Structure Definitions ---
typedef struct slist_s {
    unsigned char *domain; // RHN format
    int exact;
    int rule; // C_INCLUDED or C_EXCLUDED
} slist_t;

// Simplified slist_array for testing (manual management)
typedef struct {
    slist_t* items;
    int count;
    int capacity;
} slist_array_test_t;


typedef struct servparm_s {
    slist_array_test_t alist; // Access list
    int policy; // Default policy (C_INCLUDED, C_EXCLUDED, etc.)
    // other fields omitted for simplicity
} servparm_t;

// --- Minimal RHN and Helper Functions (simplified or direct from pdnsd source) ---

// From dns.c: rhnlen
unsigned rhnlen(const unsigned char *rhn) {
    const unsigned char *p = rhn;
    if (!rhn) return 1; // Should not happen with valid RHN, but guard for safety
    while (*p) {
        if (((p + *p + 1) - rhn) >= DNSNAMEBUFSIZE) return DNSNAMEBUFSIZE; // Prevent overflow
         p += (*p) + 1;
    }
    return (p - rhn + 1);
}

// From dns.c: rhnsegcnt 
int rhnsegcnt(const unsigned char *rhn) {
    int count = 0;
    if (!rhn || *rhn == 0) return 0; 
    while (*rhn) {
        count++;
        if (((rhn + *rhn + 1) - rhn) >= DNSNAMEBUFSIZE && *(rhn + *rhn +1) != 0) {
             // Should not happen in well-formed rhn
             return count; // Or an error
        }
        rhn += *rhn + 1;
    }
    return count;
}


// From dns.c: str2rhn_dot (simplified, assumes valid input, no compression ptrs)
const char *str2rhn_dot(const char *str, unsigned char *rhn, unsigned *lenp) {
    const char *p, *s;
    unsigned char *q, *lenbyte;
    unsigned i, cur_len = 0, totlen = 0;

    q = rhn;
    s = str;

    if (strcmp(str, ".") == 0) { // Handle root domain specially
        *q = 0;
        if (lenp) *lenp = 0; // Length of labels part is 0 for root.
        return NULL;
    }

    for (;;) {
        lenbyte = q++;
        totlen++;
        if (totlen >= DNSNAMEBUFSIZE) return "name too long (overall)";

        p = s;
        while (*s && *s != '.') s++;
        i = s - p;

        if (i > 63) return "label too long (>63)";
        if (i == 0) { // Empty label
             // Allowed only if it's the end of the string, signifying the root if string was just "" or "."
             // Here, means ".." or trailing "." on empty string if p==s and *s was '.'
            if (p == str && *s == 0 && totlen==1) { // Empty string "" -> root
                *(lenbyte) = 0; // single 0 byte for root
                goto success;
            }
            return "empty label";
        }
        
        *lenbyte = i;
        cur_len += i + 1; // current length of rhn data (labels + length bytes)
        
        if (totlen + i >= DNSNAMEBUFSIZE) return "name too long (label content)";
        memcpy(q, p, i);
        q += i;
        totlen += i;

        if (!*s) break; // End of string
        s++; /* skip dot */
        if (!*s && totlen > 1) break; // Trailing dot, e.g. "example.com."
    }
success:
    if (totlen >= DNSNAMEBUFSIZE) { // Final check for the null terminator for rhn
         *(rhn + DNSNAMEBUFSIZE -1) = 0; // Ensure null termination if overflow
         return "name too long (final)";
    }
    *q = 0; 
    totlen++; 
    if (lenp) *lenp = cur_len; // length of rhn data part, excluding final null
    return NULL; 
}

// From dns.c: rhn2str (simplified)
void rhn2str(const unsigned char *rhn, char *str, unsigned buflen) {
    unsigned len;
    char *lim;

    if (!str || buflen == 0) return;
    lim = str + buflen -1; 

    if (!rhn || *rhn == 0) { 
        if (str < lim) *str++ = '.';
        *str = 0;
        return;
    }

    while (*rhn) {
        len = *rhn++;
        if (str + len + (*rhn ? 1 : 0) > lim) { 
            *str = 0; 
            return;
        }
        memcpy(str, rhn, len);
        str += len;
        rhn += len;
        if (*rhn) *str++ = '.';
    }
    *str = 0;
}

// From dns.c: equiv_rhn
int equiv_rhn(const unsigned char *s1, const unsigned char *s2) {
    unsigned l1, l2;
    if (!s1 || !s2) return s1 == s2; // Both NULL is true, one NULL is false
    
    // Calculate lengths carefully, rhnlen is tricky for malformed
    const unsigned char *p1 = s1, *p2 = s2;
    while(*p1 && *p2 && *p1 == *p2) { // Compare label lengths
        unsigned len = *p1;
        p1++; p2++;
        if (memcmp(p1, p2, len) != 0) return 0; // Compare label contents
        p1 += len;
        p2 += len;
    }
    return *p1 == *p2; // Both should be 0 (end of RHN)
}

// --- Mock/Simplified DA_ macros and helpers ---
void free_slist_domain(slist_t *sl) {
    if (sl && sl->domain) {
        free(sl->domain);
        sl->domain = NULL;
    }
}

void alist_add(slist_array_test_t* alist, slist_t new_item) {
    if (alist->count >= alist->capacity) {
        alist->capacity = (alist->capacity == 0) ? 4 : alist->capacity * 2;
        alist->items = (slist_t*)realloc(alist->items, alist->capacity * sizeof(slist_t));
        assert(alist->items != NULL);
    }
    alist->items[alist->count++] = new_item;
}

void alist_free(slist_array_test_t* alist) {
    if (alist->items) {
        for (int i = 0; i < alist->count; ++i) {
            free_slist_domain(&alist->items[i]);
        }
        free(alist->items);
        alist->items = NULL;
        alist->count = 0;
        alist->capacity = 0;
    }
}

// --- The function to be tested (use_server from dns_query.c) ---
static int use_server(servparm_t *s, const unsigned char *name)
{
	int i, n = s->alist.count; 

	for (i = 0; i < n; i++) {
		slist_t *sl = &s->alist.items[i]; 
		if (sl->exact == 0) { 
			char qname_str[DNSNAMEBUFSIZE];
			char sldomain_str[DNSNAMEBUFSIZE];
			int qname_len, sldomain_len;

			rhn2str(name, qname_str, sizeof(qname_str));
			rhn2str(sl->domain, sldomain_str, sizeof(sldomain_str));

			qname_len = strlen(qname_str);
			sldomain_len = strlen(sldomain_str);

            if (sldomain_len == 0 && qname_len == 0 && strcmp(sldomain_str, ".") == 0 && strcmp(qname_str, ".") == 0) {
                 // Special case: rule is for root ".", query is for root "."
                 // Wildcard on root "" (from "."), exact=0 is tricky.
                 // For sl->domain being RHN {0} (from "."), sldomain_str becomes "."
                 // If qname is also RHN {0}, qname_str becomes "."
                 // This means wildcard on root matches root.
                 if (strcmp(qname_str, ".") == 0 && strcmp(sldomain_str, ".") == 0) {
                     return sl->rule == C_INCLUDED;
                 }
            } else if (sldomain_len == 0 && strcmp(sldomain_str, ".") == 0) {
                // Wildcard on root, e.g. rule ".". (exact=0)
                // This implies all domains match.
                // This case should be carefully considered if such rule is possible.
                // For now, assume sl->domain is not empty for typical wildcards like "example.com" (from ".example.com")
                // A rule like "." with exact=0 is probably not what users mean.
                // Let's assume standard wildcards sl->domain is not the bare root.
            }


			if ((qname_len == sldomain_len && strcmp(qname_str, sldomain_str) == 0) ||
			    (qname_len > sldomain_len && sldomain_len > 0 && /* ensure sldomain is not empty like "" from invalid rhn */
			     qname_str[qname_len - sldomain_len - 1] == '.' &&
			     strcmp(qname_str + qname_len - sldomain_len, sldomain_str) == 0)) {
				return sl->rule == C_INCLUDED;
			}
		} else { 
			if (equiv_rhn(name, sl->domain)) {
				return sl->rule == C_INCLUDED;
			}
		}
	}

	if (s->policy == C_SIMPLE_ONLY || s->policy == C_FQDN_ONLY) {
        if (rhnsegcnt(name) <= (name[0]==0 ? 0 : 1) ) // Root "." is 0 segments, "com." is 1 segment.
			return s->policy == C_SIMPLE_ONLY;
        else
			return s->policy == C_FQDN_ONLY;
    }
	return s->policy == C_INCLUDED;
}


// --- Test Helper Functions specific to this file ---
servparm_t* create_test_server_standalone(int default_policy) {
    servparm_t* server = (servparm_t*)malloc(sizeof(servparm_t));
    assert(server != NULL);
    server->policy = default_policy;
    server->alist.items = NULL;
    server->alist.count = 0;
    server->alist.capacity = 0;
    return server;
}

void add_server_rule_standalone(servparm_t* server, const char* domain_str, int exact, int rule_type) {
    slist_t sl_entry;
    unsigned char rhn_domain[DNSNAMEBUFSIZE];
    const char *err_str;

    // For wildcard rules (exact=0), the domain_str should be the base domain (e.g., "example.com" for ".example.com")
    // For exact rules (exact=1), domain_str is the exact domain (e.g., "exact.com", or "." for root)
    err_str = str2rhn_dot(domain_str, rhn_domain, NULL);
    if (err_str) {
        fprintf(stderr, "Test setup error: str2rhn_dot failed for domain '%s': %s\n", domain_str, err_str);
    }
    assert(err_str == NULL); 

    size_t len_rhn = rhnlen(rhn_domain);
    sl_entry.domain = (unsigned char*)malloc(len_rhn);
    assert(sl_entry.domain != NULL);
    memcpy(sl_entry.domain, rhn_domain, len_rhn);
    
    sl_entry.exact = exact;
    sl_entry.rule = rule_type;
    alist_add(&server->alist, sl_entry);
}

void free_test_server_standalone(servparm_t* server) {
    if (server) {
        alist_free(&server->alist);
        free(server);
    }
}

unsigned char rhn_buf_global_standalone[DNSNAMEBUFSIZE];
const unsigned char* r_standalone(const char* domain_str) {
    const char* err = str2rhn_dot(domain_str, rhn_buf_global_standalone, NULL);
     if (err) {
        fprintf(stderr, "Test query setup error: str2rhn_dot failed for domain '%s': %s\n", domain_str, err);
    }
    assert(err == NULL);
    return rhn_buf_global_standalone;
}


// --- Test Cases ---
void test_t1_exclusion_subdomain_wildcard() {
    printf("Running T1: Exclusion - Subdomain Wildcard...\n");
    servparm_t* server = create_test_server_standalone(C_INCLUDED); 
    add_server_rule_standalone(server, "example.com", 0, C_EXCLUDED); // Rule for ".example.com"
    assert(use_server(server, r_standalone("sub.sub.example.com")) == 0); 
    assert(use_server(server, r_standalone("sub.example.com")) == 0); 
    assert(use_server(server, r_standalone("example.com")) == 0);
    free_test_server_standalone(server);
    printf("T1 Passed.\n");
}

void test_t2_non_exclusion_wildcard() {
    printf("Running T2: Non-Exclusion (Wildcard Rule, Non-matching Domains)...\n");
    servparm_t* server_def_allow = create_test_server_standalone(C_INCLUDED); 
    add_server_rule_standalone(server_def_allow, "example.com", 0, C_EXCLUDED); // Rule for ".example.com"
    assert(use_server(server_def_allow, r_standalone("another.com")) == 1);
    assert(use_server(server_def_allow, r_standalone("com")) == 1);
    free_test_server_standalone(server_def_allow);

    servparm_t* server_def_deny = create_test_server_standalone(C_EXCLUDED); 
    add_server_rule_standalone(server_def_deny, "example.com", 0, C_EXCLUDED); // Rule for ".example.com"
    assert(use_server(server_def_deny, r_standalone("another.com")) == 0); 
    free_test_server_standalone(server_def_deny);
    printf("T2 Passed.\n");
}

void test_t3_exclusion_exact_match() {
    printf("Running T3: Exclusion - Exact Match...\n");
    servparm_t* server = create_test_server_standalone(C_INCLUDED);
    add_server_rule_standalone(server, "exact.com", 1, C_EXCLUDED);
    assert(use_server(server, r_standalone("exact.com")) == 0);
    free_test_server_standalone(server);
    printf("T3 Passed.\n");
}

void test_t4_non_exclusion_exact_subdomain() {
    printf("Running T4: Non-Exclusion (Exact Rule, Subdomain Query)...\n");
    servparm_t* server = create_test_server_standalone(C_INCLUDED);
    add_server_rule_standalone(server, "exact.com", 1, C_EXCLUDED);
    assert(use_server(server, r_standalone("sub.exact.com")) == 1);
    free_test_server_standalone(server);
    printf("T4 Passed.\n");
}

void test_t5_inclusion_rules() {
    printf("Running T5: Inclusion Rules...\n");
    servparm_t* server_wc = create_test_server_standalone(C_EXCLUDED); 
    add_server_rule_standalone(server_wc, "example.com", 0, C_INCLUDED); // Rule for ".example.com"
    assert(use_server(server_wc, r_standalone("sub.example.com")) == 1); 
    assert(use_server(server_wc, r_standalone("example.com")) == 1); 
    assert(use_server(server_wc, r_standalone("another.com")) == 0); 
    free_test_server_standalone(server_wc);

    servparm_t* server_exact = create_test_server_standalone(C_EXCLUDED); 
    add_server_rule_standalone(server_exact, "exact.com", 1, C_INCLUDED);
    assert(use_server(server_exact, r_standalone("exact.com")) == 1); 
    assert(use_server(server_exact, r_standalone("sub.exact.com")) == 0); 
    free_test_server_standalone(server_exact);
    printf("T5 Passed.\n");
}

void test_t6_root_domain() {
    printf("Running T6: Root Domain Handling...\n");
    servparm_t* server = create_test_server_standalone(C_INCLUDED); 
    add_server_rule_standalone(server, ".", 1, C_EXCLUDED); // Rule for "." (exact)
    assert(use_server(server, r_standalone(".")) == 0); 
    assert(use_server(server, r_standalone("com.")) == 1); 
    free_test_server_standalone(server);
    printf("T6 Passed.\n");
}

void test_t7_order_of_rules() {
    printf("Running T7: Order of Rules...\n");
    const unsigned char* query_name = r_standalone("www.example.com");

    servparm_t* server1 = create_test_server_standalone(C_EXCLUDED);
    add_server_rule_standalone(server1, "example.com", 0, C_INCLUDED); // .example.com
    add_server_rule_standalone(server1, "www.example.com", 1, C_EXCLUDED);
    assert(use_server(server1, query_name) == 1); // Include .example.com matches first
    free_test_server_standalone(server1);

    servparm_t* server2 = create_test_server_standalone(C_INCLUDED);
    add_server_rule_standalone(server2, "www.example.com", 1, C_EXCLUDED);
    add_server_rule_standalone(server2, "example.com", 0, C_INCLUDED); // .example.com
    assert(use_server(server2, query_name) == 0); // Exclude www.example.com matches first
    free_test_server_standalone(server2);
    
    printf("T7 Passed.\n");
}

void test_t8_large_list_stress() {
    printf("Running T8: Large List Stress Test...\n");
    servparm_t* server = create_test_server_standalone(C_INCLUDED); 
    char domain_buf[100];
    int num_rules = 500;

    for (int i = 0; i < num_rules; ++i) {
        sprintf(domain_buf, "site%d.com", i); // Domain for wildcard rule ".siteX.com"
        add_server_rule_standalone(server, domain_buf, 0, (i % 2 == 0) ? C_EXCLUDED : C_INCLUDED);
    }

    assert(use_server(server, r_standalone("nonexistent.otherdomain.com")) == 1); 
    assert(use_server(server, r_standalone("sub.site0.com")) == 0); // site0 rule is EXCLUDED
    
    sprintf(domain_buf, "host.site%d.com", num_rules - 1); // e.g. host.site499.com
    // num_rules-1 is 499. 499%2 != 0, so rule is C_INCLUDED
    assert(use_server(server, r_standalone(domain_buf)) == 1); 

    free_test_server_standalone(server);
    printf("T8 Passed.\n");
}


int main(int argc, char **argv) {
    printf("Starting standalone unit tests for use_server()...\n");

    test_t1_exclusion_subdomain_wildcard();
    test_t2_non_exclusion_wildcard();
    test_t3_exclusion_exact_match();
    test_t4_non_exclusion_exact_subdomain();
    test_t5_inclusion_rules();
    test_t6_root_domain();
    test_t7_order_of_rules();
    test_t8_large_list_stress();

    printf("All standalone use_server tests completed successfully.\n");
    return 0;
}
