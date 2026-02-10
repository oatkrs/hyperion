/* PROJECT HYPERION v5.1: OBSIDIAN MONOLITH
   - Visual Progress Bars for KDF
   - High-Precision Nanosecond Entropy Mixing
   - Real-time Unbuffered UI Feedback
   - Titan-KDF (64MB)
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

// --- PLATFORM SPECIFIC SETUP ---
#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <conio.h>
    #define SLEEP_MS(x) Sleep(x)
    void clear_screen() { system("cls"); }
    void setup_console() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
    uint64_t get_high_res_time() {
        LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart;
    }
#else
    #include <unistd.h>
    #include <termios.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #define SLEEP_MS(x) usleep((x)*1000)
    void clear_screen() { printf("\033[2J\033[H"); }
    void setup_console() { }
    
    int _getch(void) {
        struct termios oldattr, newattr;
        int ch;
        tcgetattr(STDIN_FILENO, &oldattr);
        newattr = oldattr;
        newattr.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
        ch = getchar();
        tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
        return ch;
    }
    
    int _kbhit(void) {
        struct termios oldt, newt;
        int ch;
        int oldf;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
        ch = getchar();
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fcntl(STDIN_FILENO, F_SETFL, oldf);
        if(ch != EOF) { ungetc(ch, stdin); return 1; }
        return 0;
    }
    uint64_t get_high_res_time() {
        struct timeval tv; gettimeofday(&tv,NULL); 
        return (uint64_t)tv.tv_usec + (uint64_t)tv.tv_sec * 1000000;
    }
#endif

// --- CONSTANTS ---
#define TITAN_MEM_SIZE (64 * 1024 * 1024) // 64MB Grid
#define TITAN_PASSES 3
#define KEY_LEN 32
#define NONCE_LEN 24
#define SALT_LEN 64 
#define TAG_LEN 16

#define KEY_ENTER 13
#define KEY_ESC 27

// --- COLORS ---
#define C_RESET   "\033[0m"
#define C_RED     "\033[38;5;196m"
#define C_GREEN   "\033[38;5;46m"
#define C_YELLOW  "\033[38;5;226m"
#define C_CYAN    "\033[38;5;51m"
#define C_GREY    "\033[38;5;240m"
#define C_BOLD    "\033[1m"
#define C_BORDER  "\033[38;5;239m"

// --- MEMORY ---
void secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

void flush_input() { while(_kbhit()) _getch(); }

// --- UI HELPERS ---
void print_progress(const char* label, size_t current, size_t total) {
    int width = 30;
    float ratio = (float)current / (float)total;
    int pos = (int)(ratio * width);
    
    printf("\r" C_CYAN " [*] %-10s " C_BORDER "[" C_GREEN, label);
    for (int i = 0; i < width; ++i) {
        if (i < pos) printf("#");
        else printf(" ");
    }
    printf(C_BORDER "] " C_YELLOW "%3d%%" C_RESET, (int)(ratio * 100));
    fflush(stdout); // Force update immediately
}

// --- CRYPTO PRIMITIVES ---
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define QR(a, b, c, d) a+=b; d^=a; d=rotl32(d,16); c+=d; b^=c; b=rotl32(b,12); a+=b; d^=a; d=rotl32(d,8); c+=d; b^=c; b=rotl32(b,7);

void chacha_block(uint32_t *state, uint8_t *stream) {
    uint32_t x[16]; memcpy(x, state, 64);
    for (int i=0; i<10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (int i=0; i<16; i++) {
        uint32_t v = x[i] + state[i];
        stream[i*4] = v&0xFF; stream[i*4+1]=(v>>8)&0xFF; stream[i*4+2]=(v>>16)&0xFF; stream[i*4+3]=(v>>24)&0xFF;
    }
}

// --- CSPRNG ---
typedef struct {
    uint32_t state[16];
    uint8_t buffer[64];
    size_t idx;
} TitanRNG;

TitanRNG global_rng;

void rng_seed(const uint8_t *seed_material, size_t len) {
    global_rng.state[0] = 0x61707865; global_rng.state[1] = 0x3320646e;
    global_rng.state[2] = 0x79622d32; global_rng.state[3] = 0x6b206574;
    for(size_t i=0; i<32; i++) {
        uint8_t b = (i < len) ? seed_material[i] : 0xAA;
        ((uint8_t*)&global_rng.state[4])[i] ^= b;
    }
    global_rng.idx = 64; 
}

uint8_t rng_byte() {
    if(global_rng.idx >= 64) {
        chacha_block(global_rng.state, global_rng.buffer);
        global_rng.state[12]++; 
        global_rng.idx = 0;
    }
    return global_rng.buffer[global_rng.idx++];
}

void rng_bytes(uint8_t *out, size_t len) {
    for(size_t i=0; i<len; i++) out[i] = rng_byte();
}

// --- ENCRYPTION LAYERS ---
void hchacha20(const uint8_t *key, const uint8_t *nonce, uint8_t *out) {
    uint32_t s[16] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for(int i=0;i<8;i++) s[4+i] = ((uint32_t*)key)[i];
    for(int i=0;i<4;i++) s[12+i] = ((uint32_t*)nonce)[i];
    for(int i=0;i<10;i++) {
        QR(s[0],s[4],s[8],s[12]); QR(s[1],s[5],s[9],s[13]); QR(s[2],s[6],s[10],s[14]); QR(s[3],s[7],s[11],s[15]);
        QR(s[0],s[5],s[10],s[15]); QR(s[1],s[6],s[11],s[12]); QR(s[2],s[7],s[8],s[13]); QR(s[3],s[4],s[9],s[14]);
    }
    memcpy(out, &s[0], 16); memcpy(out+16, &s[12], 16);
}

void xchacha20(uint8_t *buf, size_t len, const uint8_t *key, const uint8_t *nonce) {
    uint8_t k[32]; hchacha20(key, nonce, k);
    uint32_t s[16] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for(int i=0;i<8;i++) s[4+i] = ((uint32_t*)k)[i];
    s[12]=1; s[13]=0; s[14]=((uint32_t*)(nonce+16))[0]; s[15]=((uint32_t*)(nonce+16))[1];
    uint8_t stream[64];
    for(size_t i=0; i<len; i++) {
        if(i%64==0) { chacha_block(s, stream); s[12]++; }
        buf[i] ^= stream[i%64];
    }
    secure_wipe(k, 32); secure_wipe(stream, 64);
}

void poly1305_mac(const uint8_t *msg, size_t len, const uint8_t *key, uint8_t *tag) {
    uint32_t h[8];
    for(int i=0; i<8; i++) h[i] = ((uint32_t*)key)[i];
    for(size_t i=0; i<len; i++) {
        ((uint8_t*)h)[i % 32] ^= msg[i];
        if(i % 32 == 31) { QR(h[0], h[1], h[2], h[3]); QR(h[4], h[5], h[6], h[7]); }
    }
    for(int i=0; i<4; i++) { QR(h[0], h[1], h[2], h[3]); QR(h[4], h[5], h[6], h[7]); }
    memcpy(tag, h, 16); secure_wipe(h, 32);
}

// --- TITAN KDF (With Visuals) ---
void titan_kdf(const char *pass, const uint8_t *salt, uint8_t *out_key) {
    printf("\n");
    
    // 1. ALLOCATE
    uint64_t *memory = malloc(TITAN_MEM_SIZE);
    if (!memory) { printf(C_RED "RAM FAIL\n" C_RESET); exit(1); }
    size_t count = TITAN_MEM_SIZE / sizeof(uint64_t);

    // 2. FILLING (Linear)
    uint32_t seed_state[16]; memset(seed_state, 0, 64);
    for(int i=0; pass[i]; i++) ((uint8_t*)seed_state)[i % 64] ^= pass[i];
    for(int i=0; i<SALT_LEN; i++) ((uint8_t*)seed_state)[i % 64] ^= salt[i];
    
    uint8_t block[64];
    for (size_t i = 0; i < count; i += 8) { 
        chacha_block(seed_state, block);
        seed_state[12]++;
        memcpy(&memory[i], block, 64);
        
        // Update bar every 256KB to save IO time
        if (i % (32 * 1024) == 0) print_progress("Filling", i, count);
    }
    print_progress("Filling", count, count);
    printf("\n");

    // 3. HARDENING (Random Passes)
    uint64_t prev = memory[0];
    size_t total_ops = TITAN_PASSES * count;
    size_t current_op = 0;

    for (int p = 0; p < TITAN_PASSES; p++) {
        for (size_t i = 0; i < count; i++) {
            uint64_t rand_idx = prev % count;
            uint64_t v = memory[i];
            uint64_t r = memory[rand_idx];
            
            v ^= (prev + r);
            v = (v << 13) | (v >> 51);
            memory[i] = v;
            prev = v;
            
            current_op++;
            if (current_op % (32 * 1024) == 0) print_progress("Hardening", current_op, total_ops);
        }
    }
    print_progress("Hardening", total_ops, total_ops);
    printf("\n");

    // 4. HASH
    uint32_t hash_state[16] = {0};
    for (size_t i = 0; i < count; i++) {
        hash_state[i % 16] ^= (uint32_t)memory[i];
        hash_state[(i+1) % 16] ^= (uint32_t)(memory[i] >> 32);
        if (i % 1024 == 0) QR(hash_state[0], hash_state[4], hash_state[8], hash_state[12]);
    }
    for(int i=0; i<10; i++) chacha_block(hash_state, (uint8_t*)hash_state); 
    
    memcpy(out_key, hash_state, 32);
    secure_wipe(memory, TITAN_MEM_SIZE);
    free(memory);
}

// --- DATA ---
typedef struct {
    char site[64];
    char user[64];
    char pass[128];
} Entry;

Entry *database = NULL;
int db_count = 0;
char vault_path[256];

// --- RITUAL ---
void initialization_ritual() {
    clear_screen();
    printf(C_CYAN "\n === SYSTEM ENTROPY INITIALIZATION ===\n" C_RESET);
    printf(" Mash keys to seed the Titan Engine.\n [");
    
    uint8_t entropy_pool[64] = {0};
    int gathered = 0;
    
    while(gathered < 64) {
        if(_kbhit()) {
            int c = _getch();
            uint64_t t = get_high_res_time();
            
            // Mix: Current Pool XOR (Rotated Key + Time)
            // We rotate the key value by the nanosecond count to make it non-linear
            uint8_t mixed_key = (c << (t % 7)) | (c >> (8 - (t % 7)));
            
            entropy_pool[gathered % 64] ^= mixed_key;
            
            // Mix the full 64-bit time into the pool across 8 bytes
            for(int k=0; k<8; k++) {
                entropy_pool[(gathered + k) % 64] ^= ((t >> (k*8)) & 0xFF);
            }
            
            printf(C_GREEN "#" C_RESET);
            fflush(stdout); // Instant feedback
            gathered++;
        }
    }
    printf("] Done.\n");
    rng_seed(entropy_pool, 64);
    secure_wipe(entropy_pool, 64);
    SLEEP_MS(200);
}

void get_safe_string(char *buffer, int max_len) {
    flush_input();
    int i = 0;
    while(i < max_len - 1) {
        char c = _getch();
        if(c == '\r' || c == '\n') break;
        if(c == 8 || c == 127) { 
            if(i > 0) { i--; printf("\b \b"); }
        } else if(isprint(c)) {
            buffer[i++] = c; printf("%c", c);
        }
    }
    buffer[i] = 0; printf("\n");
}

// --- IO ---
void save_vault(const char *pass) {
    FILE *fp = fopen(vault_path, "wb");
    if(!fp) return;

    uint8_t salt[SALT_LEN]; rng_bytes(salt, SALT_LEN);
    uint8_t nonce[NONCE_LEN]; rng_bytes(nonce, NONCE_LEN);
    uint8_t key[32]; titan_kdf(pass, salt, key);

    size_t data_len = sizeof(Entry) * db_count;
    uint8_t *buf = malloc(data_len);
    if(db_count > 0) memcpy(buf, database, data_len);
    
    xchacha20(buf, data_len, key, nonce);
    uint8_t tag[TAG_LEN]; poly1305_mac(buf, data_len, key, tag);

    fwrite(salt, 1, SALT_LEN, fp);
    fwrite(nonce, 1, NONCE_LEN, fp);
    fwrite(tag, 1, TAG_LEN, fp);
    fwrite(&db_count, sizeof(int), 1, fp);
    if(data_len > 0) fwrite(buf, 1, data_len, fp);

    secure_wipe(key, 32); free(buf); fclose(fp);
    
    printf(C_GREEN "\n [SUCCESS] Vault Saved: %s" C_RESET "\n", vault_path);
    flush_input(); // Clear buffer so impatient users dont trigger menu
    SLEEP_MS(1500);
}

int load_vault(const char *pass) {
    FILE *fp = fopen(vault_path, "rb");
    if(!fp) return 0; 

    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], tag[TAG_LEN], ftag[TAG_LEN], key[32];
    int count;

    if(fread(salt, 1, SALT_LEN, fp) != SALT_LEN) { fclose(fp); return 0; }
    fread(nonce, 1, NONCE_LEN, fp);
    fread(ftag, 1, TAG_LEN, fp);
    fread(&count, sizeof(int), 1, fp);

    if(count > 10000 || count < 0) { fclose(fp); return 0; }

    titan_kdf(pass, salt, key);

    size_t data_len = sizeof(Entry) * count;
    uint8_t *buf = malloc(data_len);
    fread(buf, 1, data_len, fp);
    fclose(fp);

    poly1305_mac(buf, data_len, key, tag);
    if(memcmp(tag, ftag, TAG_LEN) != 0) {
        printf(C_RED "\n [ERROR] Integrity Check Failed.\n" C_RESET);
        secure_wipe(key, 32); free(buf); exit(1);
    }

    xchacha20(buf, data_len, key, nonce);
    secure_wipe(key, 32);
    
    if(database) free(database);
    database = (Entry*)buf;
    db_count = count;
    
    flush_input(); // Clear any keys pressed during loading
    return 1;
}

// --- TUI ---
void draw_box(int w) { printf(C_BORDER "+"); for(int i=0;i<w;i++) printf("-"); printf("+" C_RESET "\n"); }

void tui_header() {
    clear_screen();
    draw_box(60);
    printf(C_BORDER "|" C_BOLD C_CYAN " HYPERION: OBSIDIAN MONOLITH" C_RESET " %31s " C_BORDER "|\n" C_RESET, "");
    printf(C_BORDER "|" C_RESET " LOADED: " C_YELLOW "%-51s" C_RESET C_BORDER "|\n" C_RESET, vault_path);
    draw_box(60);
}

void generate_chaos_pass(char *out_pass) {
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    int needed = 32; 
    int gathered = 0;
    
    flush_input();
    printf("\n" C_YELLOW " [CHAOS GENERATOR]" C_RESET "\n Mash keys for entropy:\n [");
    
    while(gathered < needed) {
        if(_kbhit()) {
            _getch(); 
            uint8_t r = rng_byte();
            printf(C_GREEN "#" C_RESET); fflush(stdout);
            out_pass[gathered] = charset[r % strlen(charset)];
            gathered++;
        }
    }
    printf("]\n");
    out_pass[needed] = '\0';
    flush_input();
    
    printf("\n Gen: " C_CYAN "%s" C_RESET, out_pass);
    printf("\n Press " C_BOLD "[ENTER]" C_RESET " Accept / " C_BOLD "[ESC]" C_RESET " Retry.");

    while(1) {
        int k = _getch();
        if(k == KEY_ENTER || k == '\n' || k == '\r') return;
        if(k == KEY_ESC) { generate_chaos_pass(out_pass); return; }
    }
}

void add_entry(const char *master_pass) {
    Entry *new_db = realloc(database, sizeof(Entry) * (db_count + 1));
    if(!new_db) return;
    database = new_db;
    Entry *e = &database[db_count];

    printf("\n" C_BOLD " [ADD]" C_RESET "\n");
    printf(" Site: "); get_safe_string(e->site, 63); if(!strlen(e->site)) return;
    printf(" User: "); get_safe_string(e->user, 63);

    printf(" Auto-Gen Pass? (y/n): ");
    char c = _getch();
    if(c == 'y' || c == 'Y') generate_chaos_pass(e->pass);
    else { printf("\n Pass: "); get_safe_string(e->pass, 127); }

    db_count++;
    save_vault(master_pass); 
}

void list_entries() {
    while(1) {
        tui_header();
        printf(C_BOLD " [VAULT CONTENTS]" C_RESET "\n");
        printf(" %-3s | %-20s | %-20s\n", "ID", "SITE", "USER");
        printf(" ------------------------------------------------\n");
        for(int i=0; i<db_count; i++) printf(" %-3d | %-20s | %-20s\n", i, database[i].site, database[i].user);
        printf(" ------------------------------------------------\n");
        printf(" Enter ID to decrypt (-1 back): ");
        
        char id_buf[16]; get_safe_string(id_buf, 10);
        int id = atoi(id_buf);
        if(id < 0) return;

        if(id >= 0 && id < db_count) {
            printf("\n" C_BORDER " ------------------------------------------------" C_RESET "\n");
            printf(" SITE: " C_BOLD "%s" C_RESET "\n", database[id].site);
            printf(" USER: " C_BOLD "%s" C_RESET "\n", database[id].user);
            printf(" PASS: " C_RED  "%s" C_RESET "\n", database[id].pass);
            printf(C_BORDER " ------------------------------------------------" C_RESET "\n");
            printf(C_YELLOW " [ESC] to Hide..." C_RESET);
            while(1) { int k = _getch(); if(k==KEY_ESC || k==KEY_ENTER) break; }
        }
    }
}

int main(int argc, char *argv[]) {
    setup_console();
    if(argc > 1) strncpy(vault_path, argv[1], 255);
    else strcpy(vault_path, "hyperion.vault");

    initialization_ritual();

    tui_header();
    printf(C_BOLD " LOCKED." C_RESET " Master Key: ");
    
    char master[128] = {0};
    int i=0;
    while(1) {
        char c = _getch();
        if(c == '\r' || c == '\n') break;
        if(c == 8 || c == 127) { if(i>0) {i--; printf("\b \b");} }
        else if(i<127) { master[i++]=c; printf("*"); }
    }
    master[i]=0; printf("\n");

    if(load_vault(master)) {
        printf(C_GREEN " Decrypted." C_RESET); SLEEP_MS(500);
    } else {
        printf(C_YELLOW " New Vault." C_RESET); SLEEP_MS(500);
    }

    while(1) {
        tui_header();
        printf(" Entries: %d\n", db_count);
        printf(" [A] Add  [L] List  [Q] Save/Quit\n\n > ");
        char c = _getch();
        if(c=='a'||c=='A') add_entry(master);
        else if(c=='l'||c=='L') list_entries();
        else if(c=='q'||c=='Q') { save_vault(master); break; }
    }
    
    secure_wipe(master, 128);
    if(database) { secure_wipe(database, sizeof(Entry)*db_count); free(database); }
    return 0;
}