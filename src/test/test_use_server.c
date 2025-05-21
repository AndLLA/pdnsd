#include <config.h> // Should be found via AM_CPPFLAGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h> // For pthread_self, PTHREAD_MUTEX_INITIALIZER

// Minimal stubs/definitions for globals if not fully handled by linked .o files.
// These are defined in their respective .c files, which are compiled to .o and linked.
// So, direct definition here should ideally not be needed IF linking is correct.
// However, for `global` and `serv_presets`, they need to be initialized.
// extern globparm_t global; // From conff.c
// extern servparm_t serv_presets; // From conff.c
// extern pthread_t main_thrid; // From thread.c
// extern pthread_attr_t attr_detached; // From thread.c

// Actual global variables that will be properly defined by linked .o files.
// We declare them extern here so this file knows about them.
// The definitions are in conff.c, thread.c etc.
extern globparm_t global;
extern servparm_t serv_presets;
extern pthread_t main_thrid;
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 16384 /* A common default if not defined */
#endif
pthread_attr_t attr_detached; // Definition for thread.c if it's not linked for some reason or needs it early.


// Function prototypes for what we might use from linked objects
// For init_global_preset_vars() from conff.c
void init_global_preset_vars(void);
// For str2rhn_dot() and other dns.c functions
const char *str2rhn_dot(const char *str, unsigned char *rhn, unsigned *lenp);
// unsigned rhnlen(const unsigned char *rhn); // Comes from dns_query.c include
// int rhnsegcnt(const unsigned char *rhn); // Comes from dns_query.c include
// int equiv_rhn(const unsigned char *s1, const unsigned char *s2); // Comes from dns_query.c include
// void rhn2str(const unsigned char *rhn, char *str, unsigned buflen); // Comes from dns_query.c include


// To resolve dependencies for dns_query.c when it's included:
// It seems including the .c files directly is a robust way for unit testing static functions
// when the alternative is complex Makefile manipulations for test-specific builds.
#include "../debug.c" // For DEBUG_MSG and other macros, if used by dns_query.c
#include "../error.c" // For log_error, etc.
#include "../consts.c"  // For C_INCLUDED, C_EXCLUDED, etc.
#include "../list.c"    // If dns_query.c uses list.c's static functions or macros not in list.h
#include "../helpers.c" // For get_rand16, etc. if needed by included dns_query.c parts
#include "../dns.c"     // For rhn functions, str2rhn_dot, etc.
#include "../cache.c"   // For cache structures/functions if dns_query.c uses them directly
                        // This is getting extensive, ideally linking .o files is cleaner if static access wasn't needed.
                        // For use_server, it primarily needs structures and DA_ macros from conff.h, and rhn functions.

// servers.h is included by dns_query.c, and servers.c defines some globals.
// Let's ensure critical ones for use_server context are available or mocked if not linked.
// servers.o is in DNS_QUERY_ALL_OBJS, so its globals should be linked.
// pthread_mutex_t servers_lock = PTHREAD_MUTEX_INITIALIZER; // From servers.c (linked)
// volatile int signal_interrupt=0; // from servers.c (linked)
// short retest_flag=0; // from servers.c (linked)
// char schm[32]; // from servers.c (linked)
// pthread_cond_t server_data_cond = PTHREAD_COND_INITIALIZER; // from servers.c (linked)
// pthread_cond_t server_test_cond = PTHREAD_COND_INITIALIZER; // from servers.c (linked)
// int server_data_users = 0, server_status_ping = 0; // from servers.c (linked)

// Finally, the unit under test
#include "../dns_query.c" // This will bring in use_server

// --- Test Helper Functions ---

servparm_t* create_test_server(int default_policy) {
    servparm_t* server = (servparm_t*)malloc(sizeof(servparm_t));
    assert(server != NULL);
    
    *server = serv_presets; 
    server->policy = default_policy;
    server->alist = NULL; 
    server->label = NULL; 
    server->reject_a4 = NULL;
    server->reject_a6 = NULL;
    server->uptest_cmd = NULL;
    server->uptest_usr[0] = '\0';
    server->query_test_name = NULL;
    server->scheme[0] = '\0';
    server->interface[0] = '\0';
    server->device[0] = '\0';
    server->atup_a = NULL;
    return server;
}

void add_server_rule(servparm_t* server, const char* domain_str, int exact, int rule_type) {
    slist_t sl_entry; // Use a temporary stack variable for slist_t
    unsigned char rhn_domain[DNSNAMEBUFSIZE];
    const char *err_str;

    err_str = str2rhn_dot(domain_str, rhn_domain, NULL); // Uses str2rhn_dot from dns.c
    if (err_str) {
        fprintf(stderr, "Error converting domain string '%s': %s\n", domain_str, err_str);
    }
    assert(err_str == NULL); 

    size_t len_rhn = rhnlen(rhn_domain); // rhnlen from dns.c
    sl_entry.domain = (unsigned char*)malloc(len_rhn);
    assert(sl_entry.domain != NULL);
    memcpy(sl_entry.domain, rhn_domain, len_rhn);
    
    sl_entry.exact = exact;
    sl_entry.rule = rule_type;

    // DA_GROW1_F and DA_LAST are macros from conff.h, used with dynamic arrays
    if (!(server->alist = DA_GROW1_F(server->alist, free_slist_domain))) {
        assert(0 && "Failed to grow alist");
    }
    DA_LAST(server->alist) = sl_entry; 
}

void free_test_server(servparm_t* server) {
    if (server) {
        if (server->alist) {
            DA_FREE_F(server->alist, free_slist_domain); // free_slist_domain from conff.c
        }
        free(server->label);
        free(server->uptest_cmd);
        free(server->query_test_name);
        free(server);
    }
}

unsigned char rhn_buf_global[DNSNAMEBUFSIZE]; // Reusable buffer for query names
const unsigned char* r(const char* domain_str) {
    const char* err = str2rhn_dot(domain_str, rhn_buf_global, NULL);
    assert(err == NULL);
    return rhn_buf_global;
}

// --- Test Cases ---

void test_t1_exclusion_subdomain_wildcard() {
    printf("Running T1: Exclusion - Subdomain Wildcard...\n");
    servparm_t* server = create_test_server(C_INCLUDED); 
    add_server_rule(server, ".example.com", 0, C_EXCLUDED);

    assert(use_server(server, r("sub.sub.example.com")) == 0); 
    assert(use_server(server, r("sub.example.com")) == 0); 
    assert(use_server(server, r("example.com")) == 0); // Wildcard matches base

    free_test_server(server);
    printf("T1 Passed.\n");
}

void test_t2_non_exclusion_wildcard() {
    printf("Running T2: Non-Exclusion (Wildcard Rule, Non-matching Domains)...\n");
    servparm_t* server_def_allow = create_test_server(C_INCLUDED); 
    add_server_rule(server_def_allow, ".example.com", 0, C_EXCLUDED);
    assert(use_server(server_def_allow, r("another.com")) == 1);
    assert(use_server(server_def_allow, r("com")) == 1);
    free_test_server(server_def_allow);

    servparm_t* server_def_deny = create_test_server(C_EXCLUDED); 
    add_server_rule(server_def_deny, ".example.com", 0, C_EXCLUDED);
    assert(use_server(server_def_deny, r("another.com")) == 0); 
    free_test_server(server_def_deny);
    printf("T2 Passed.\n");
}

void test_t3_exclusion_exact_match() {
    printf("Running T3: Exclusion - Exact Match...\n");
    servparm_t* server = create_test_server(C_INCLUDED);
    add_server_rule(server, "exact.com", 1, C_EXCLUDED);
    assert(use_server(server, r("exact.com")) == 0);
    free_test_server(server);
    printf("T3 Passed.\n");
}

void test_t4_non_exclusion_exact_subdomain() {
    printf("Running T4: Non-Exclusion (Exact Rule, Subdomain Query)...\n");
    servparm_t* server = create_test_server(C_INCLUDED);
    add_server_rule(server, "exact.com", 1, C_EXCLUDED);
    assert(use_server(server, r("sub.exact.com")) == 1);
    free_test_server(server);
    printf("T4 Passed.\n");
}

void test_t5_inclusion_rules() {
    printf("Running T5: Inclusion Rules...\n");
    servparm_t* server_wc = create_test_server(C_EXCLUDED); 
    add_server_rule(server_wc, ".example.com", 0, C_INCLUDED);
    assert(use_server(server_wc, r("sub.example.com")) == 1); 
    assert(use_server(server_wc, r("example.com")) == 1); 
    assert(use_server(server_wc, r("another.com")) == 0); 
    free_test_server(server_wc);

    servparm_t* server_exact = create_test_server(C_EXCLUDED); 
    add_server_rule(server_exact, "exact.com", 1, C_INCLUDED);
    assert(use_server(server_exact, r("exact.com")) == 1); 
    assert(use_server(server_exact, r("sub.exact.com")) == 0); 
    free_test_server(server_exact);
    printf("T5 Passed.\n");
}

void test_t6_root_domain() {
    printf("Running T6: Root Domain Handling...\n");
    servparm_t* server = create_test_server(C_INCLUDED); 
    add_server_rule(server, ".", 1, C_EXCLUDED); 
    assert(use_server(server, r(".")) == 0); 
    assert(use_server(server, r("com.")) == 1); 
    free_test_server(server);
    printf("T6 Passed.\n");
}

void test_t7_order_of_rules() {
    printf("Running T7: Order of Rules...\n");
    const unsigned char* query_name = r("www.example.com");

    servparm_t* server1 = create_test_server(C_EXCLUDED);
    add_server_rule(server1, ".example.com", 0, C_INCLUDED);
    add_server_rule(server1, "www.example.com", 1, C_EXCLUDED);
    assert(use_server(server1, query_name) == 1); // Include .example.com matches first
    free_test_server(server1);

    servparm_t* server2 = create_test_server(C_INCLUDED);
    add_server_rule(server2, "www.example.com", 1, C_EXCLUDED);
    add_server_rule(server2, ".example.com", 0, C_INCLUDED);
    assert(use_server(server2, query_name) == 0); // Exclude www.example.com matches first
    free_test_server(server2);
    
    printf("T7 Passed.\n");
}

void test_t8_large_list_stress() {
    printf("Running T8: Large List Stress Test...\n");
    servparm_t* server = create_test_server(C_INCLUDED); 
    char domain_buf[100];
    int num_rules = 500; // Reduced for faster unit test execution if 1000 is too slow

    for (int i = 0; i < num_rules; ++i) {
        sprintf(domain_buf, ".site%d.com", i);
        add_server_rule(server, domain_buf, 0, (i % 2 == 0) ? C_EXCLUDED : C_INCLUDED);
    }

    assert(use_server(server, r("nonexistent.otherdomain.com")) == 1); 
    assert(use_server(server, r("sub.site0.com")) == 0); 
    // num_rules-1: if num_rules=500, i=499. 499%2 != 0 -> C_INCLUDED
    sprintf(domain_buf, "host.site%d.com", num_rules - 1);
    assert(use_server(server, r(domain_buf)) == 1); 

    free_test_server(server);
    printf("T8 Passed.\n");
}

int main(int argc, char **argv) {
    // Initialize pdnsd's global variables and presets
    init_global_preset_vars(); // From conff.c
    main_thrid = pthread_self(); // From thread.c (main_thrid might be used by logging/debug macros)
    
    // Initialize pthread attributes for detached threads (if any code path in included files needs it)
    // This is normally done in main() of pdnsd
    if (pthread_attr_init(&attr_detached) != 0) {
        perror("pthread_attr_init");
        return 1;
    }
    if (pthread_attr_setdetachstate(&attr_detached, PTHREAD_CREATE_DETACHED) != 0) {
        perror("pthread_attr_setdetachstate");
        pthread_attr_destroy(&attr_detached);
        return 1;
    }
    // Minimal initialization for global.query_port_start etc. if not set by init_global_preset_vars
    // global.query_port_start = 1024; // Example, if needed
    // global.query_port_end = 65535;   // Example, if needed

    printf("Starting unit tests for use_server()...\n");

    test_t1_exclusion_subdomain_wildcard();
    test_t2_non_exclusion_wildcard();
    test_t3_exclusion_exact_match();
    test_t4_non_exclusion_exact_subdomain();
    test_t5_inclusion_rules();
    test_t6_root_domain();
    test_t7_order_of_rules();
    test_t8_large_list_stress();

    printf("All test_use_server tests completed successfully.\n");
    
    pthread_attr_destroy(&attr_detached);
    return 0;
}
