/* HYPERION BRIDGE: CSV TO TITAN VAULT CONVERTER
   - Imports Google Chrome/Edge/Brave CSV exports
   - Encrypts using Titan-KDF + XChaCha20-Poly1305
   - output compatible with Hyperion v5.0
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

// --- PLATFORM COMPATIBILITY ---
#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #include <conio.h>
    #define SLEEP_MS(x) Sleep(x)
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
    int _getch(void) { return _getch(); } // Utilize conio's getch
#else
    #include <unistd.h>
    #include <termios.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #define SLEEP_MS(x) usleep((x)*1000)
    void setup_console() { }
    uint64_t get_high_res_time() {
        struct timeval tv; gettimeofday(&tv,NULL); 
        return (uint64_t)tv.tv_usec + (uint64_t)tv.tv_sec * 1000000;
    }
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
#endif

// --- CONFIG ---
#define TITAN_MEM_SIZE (64 * 1024 * 1024)
#define TITAN_PASSES 3
#define SALT_LEN 64
#define NONCE_LEN 24
#define TAG_LEN 16

// --- COLORS ---
#define C_RESET   "\033[0m"
#define C_GREEN   "\033[38;5;46m"
#define C_YELLOW  "\033[38;5;226m"
#define C_CYAN    "\033[38;5;51m"
#define C_RED     "\033[38;5;196m"
#define C_BOLD    "\033[1m"

// --- CRYPTO ENGINE ---
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
#define QR(a, b, c, d) a+=b; d^=a; d=rotl32(d,16); c+=d; b^=c; b=rotl32(b,12); a+=b; d^=a; d=rotl32(d,8); c+=d; b^=c; b=rotl32(b,7);

void secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

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

// Simple CSPRNG for salt/nonce generation
void get_random_bytes(uint8_t *out, size_t len) {
    uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    
    // Seed with time 
    uint64_t t = get_high_res_time();
    state[4] = (uint32_t)t; state[5] = (uint32_t)(t >> 32);
    
    // FIX: Properly cast 64-bit pointer to two 32-bit integers to avoid warning & capture full address entropy
    uintptr_t stack_addr = (uintptr_t)&out;
    state[6] = (uint32_t)stack_addr; 
    state[7] = (uint32_t)(stack_addr >> 32);
    
    uint8_t block[64];
    size_t generated = 0;
    while(generated < len) {
        chacha_block(state, block);
        state[12]++;
        size_t chunk = (len - generated > 64) ? 64 : (len - generated);
        memcpy(out + generated, block, chunk);
        generated += chunk;
    }
}

// --- TITAN KDF ---
void print_progress(const char* label, size_t current, size_t total) {
    int width = 30; float ratio = (float)current / (float)total; int pos = (int)(ratio * width);
    printf("\r" C_CYAN " [*] %-10s " C_YELLOW "[" C_GREEN, label);
    for (int i = 0; i < width; ++i) printf(i < pos ? "#" : " ");
    printf(C_YELLOW "] %3d%%" C_RESET, (int)(ratio * 100)); fflush(stdout);
}

void titan_kdf(const char *pass, const uint8_t *salt, uint8_t *out_key) {
    printf("\n");
    uint64_t *memory = malloc(TITAN_MEM_SIZE);
    if (!memory) exit(1);
    size_t count = TITAN_MEM_SIZE / sizeof(uint64_t);

    uint32_t seed_state[16]; memset(seed_state, 0, 64);
    for(int i=0; pass[i]; i++) ((uint8_t*)seed_state)[i % 64] ^= pass[i];
    for(int i=0; i<SALT_LEN; i++) ((uint8_t*)seed_state)[i % 64] ^= salt[i];
    
    uint8_t block[64];
    for (size_t i = 0; i < count; i += 8) { 
        chacha_block(seed_state, block); seed_state[12]++; memcpy(&memory[i], block, 64);
        if (i % (64 * 1024) == 0) print_progress("Filling", i, count);
    }
    print_progress("Filling", count, count); printf("\n");

    uint64_t prev = memory[0];
    size_t total_ops = TITAN_PASSES * count; size_t current_op = 0;
    for (int p = 0; p < TITAN_PASSES; p++) {
        for (size_t i = 0; i < count; i++) {
            uint64_t rand_idx = prev % count;
            uint64_t v = memory[i] ^ (prev + memory[rand_idx]);
            v = (v << 13) | (v >> 51);
            memory[i] = v; prev = v; current_op++;
            if (current_op % (64 * 1024) == 0) print_progress("Hardening", current_op, total_ops);
        }
    }
    print_progress("Hardening", total_ops, total_ops); printf("\n");

    uint32_t hash_state[16] = {0};
    for (size_t i = 0; i < count; i++) {
        hash_state[i % 16] ^= (uint32_t)memory[i];
        hash_state[(i+1) % 16] ^= (uint32_t)(memory[i] >> 32);
        if (i % 1024 == 0) QR(hash_state[0], hash_state[4], hash_state[8], hash_state[12]);
    }
    for(int i=0; i<10; i++) chacha_block(hash_state, (uint8_t*)hash_state); 
    memcpy(out_key, hash_state, 32);
    free(memory);
}

// --- ENCRYPTION ---
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
}

void poly1305_mac(const uint8_t *msg, size_t len, const uint8_t *key, uint8_t *tag) {
    uint32_t h[8]; for(int i=0; i<8; i++) h[i] = ((uint32_t*)key)[i];
    for(size_t i=0; i<len; i++) {
        ((uint8_t*)h)[i % 32] ^= msg[i];
        if(i % 32 == 31) { QR(h[0], h[1], h[2], h[3]); QR(h[4], h[5], h[6], h[7]); }
    }
    for(int i=0; i<4; i++) { QR(h[0], h[1], h[2], h[3]); QR(h[4], h[5], h[6], h[7]); }
    memcpy(tag, h, 16);
}

// --- CSV PARSING ---
typedef struct {
    char site[64];
    char user[64];
    char pass[128];
} Entry;

int get_col_index(char **headers, int count, const char *target) {
    for (int i=0; i<count; i++) {
        if (strcasecmp(headers[i], target) == 0) return i;
    }
    return -1;
}

int parse_csv_line(char *line, char **fields, int max_fields) {
    int field_count = 0;
    char *ptr = line;
    int in_quote = 0;
    
    fields[field_count++] = ptr;
    
    while (*ptr && field_count < max_fields) {
        if (*ptr == '"') {
            in_quote = !in_quote;
        } else if (*ptr == ',' && !in_quote) {
            *ptr = '\0'; 
            fields[field_count++] = ptr + 1; 
        }
        ptr++;
    }
    return field_count;
}

void clean_csv_field(char *dest, const char *src, int max_len) {
    int len = strlen(src);
    if (len == 0) { dest[0] = 0; return; }
    
    int s = 0, d = 0;
    if (src[0] == '"' && src[len-1] == '"') {
        s = 1; len--; 
    }
    
    while (s < len && d < max_len - 1) {
        if (src[s] == '"' && src[s+1] == '"') {
            dest[d++] = '"'; s += 2;
        } else {
            dest[d++] = src[s++];
        }
    }
    dest[d] = 0;
}

int main(int argc, char *argv[]) {
    setup_console();
    
    printf(C_CYAN "========================================\n");
    printf("   HYPERION BRIDGE: CSV IMPORTER\n");
    printf("========================================\n" C_RESET);

    char csv_path[256];
    if (argc > 1) strcpy(csv_path, argv[1]);
    else {
        printf("Enter path to CSV file: ");
        if (!fgets(csv_path, 256, stdin)) return 0;
        csv_path[strcspn(csv_path, "\n")] = 0;
    }

    FILE *f = fopen(csv_path, "r");
    if (!f) { printf(C_RED "Error: Could not open file %s\n" C_RESET, csv_path); return 1; }

    char line_buf[4096];
    if (!fgets(line_buf, sizeof(line_buf), f)) return 1;
    
    char *start = line_buf;
    if ((unsigned char)line_buf[0] == 0xEF && (unsigned char)line_buf[1] == 0xBB && (unsigned char)line_buf[2] == 0xBF) {
        start += 3;
    }
    start[strcspn(start, "\r\n")] = 0;

    char *headers[20];
    int col_count = parse_csv_line(start, headers, 20);
    
    int idx_name = get_col_index(headers, col_count, "name");
    int idx_url = get_col_index(headers, col_count, "url");
    int idx_user = get_col_index(headers, col_count, "username");
    int idx_pass = get_col_index(headers, col_count, "password");
    
    if (idx_name == -1 && idx_url != -1) idx_name = idx_url; 
    
    printf("Mapping: Site=[Col %d] User=[Col %d] Pass=[Col %d]\n", idx_name, idx_user, idx_pass);
    if (idx_name == -1 || idx_pass == -1) {
        printf(C_RED "Critical Error: Could not find 'name/url' or 'password' columns.\n" C_RESET);
        return 1;
    }

    Entry *entries = NULL;
    int count = 0;
    
    while (fgets(line_buf, sizeof(line_buf), f)) {
        line_buf[strcspn(line_buf, "\r\n")] = 0;
        if (strlen(line_buf) == 0) continue;
        
        char *cols[20];
        int c = parse_csv_line(line_buf, cols, 20);
        
        entries = realloc(entries, sizeof(Entry) * (count + 1));
        Entry *e = &entries[count];
        memset(e, 0, sizeof(Entry));
        
        if (idx_name < c) clean_csv_field(e->site, cols[idx_name], 63);
        if (idx_user < c && idx_user != -1) clean_csv_field(e->user, cols[idx_user], 63);
        if (idx_pass < c) clean_csv_field(e->pass, cols[idx_pass], 127);
        
        if (strlen(e->pass) > 0) {
            printf("Importing: %-20s | %s\n", e->site, e->user);
            count++;
        }
    }
    fclose(f);
    printf(C_GREEN "\nParsed %d entries successfully.\n" C_RESET, count);

    char master[128];
    printf("\nSet Master Password for New Vault: ");
    
    int i=0;
    while(1) {
        char c = _getch();
        if(c == '\r' || c == '\n') break;
        if(c == 8 || c == 127) { if(i>0) {i--; printf("\b \b");} }
        else if(i<127) { master[i++]=c; printf("*"); }
    }
    master[i] = 0; printf("\n");

    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], key[32], tag[TAG_LEN];
    get_random_bytes(salt, SALT_LEN);
    get_random_bytes(nonce, NONCE_LEN);
    
    printf(C_YELLOW "Engaging Titan-KDF... this may take a moment.\n" C_RESET);
    titan_kdf(master, salt, key);

    size_t data_len = sizeof(Entry) * count;
    uint8_t *buf = malloc(data_len);
    memcpy(buf, entries, data_len);

    xchacha20(buf, data_len, key, nonce);
    poly1305_mac(buf, data_len, key, tag);

    FILE *out = fopen("imported.vault", "wb");
    fwrite(salt, 1, SALT_LEN, out);
    fwrite(nonce, 1, NONCE_LEN, out);
    fwrite(tag, 1, TAG_LEN, out);
    fwrite(&count, sizeof(int), 1, out);
    fwrite(buf, 1, data_len, out);
    fclose(out);

    printf(C_GREEN "\n[SUCCESS] Created 'imported.vault' compatible with Hyperion v5.\n" C_RESET);
    printf("You may now delete the insecure CSV file.\n");

    free(buf);
    free(entries);
    return 0;
}