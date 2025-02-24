#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// Αριθμός γύρων για τον TEA
#define ROUNDS 32
#define DELTA 0x9e3779b9 // Σταθερά για τον αλγόριθμο TEA

void TEA_encrypt(uint32_t *v, uint32_t *k);
void TEA_decrypt(uint32_t *v, uint32_t *k);
void generate_subkeys(uint32_t initial_key, uint32_t *subkeys);
void measure_performance(uint32_t* key, size_t num_messages);

int main(){
    char *fname_M_C = "M_C_pairs.txt";
    char *fname_K_C = "K_C_pairs.txt";

    // Δημιουργία διανυσμάτων ελέγχου
    FILE *file_M_C = fopen(fname_M_C, "w");
    FILE *file_K_C = fopen(fname_K_C, "w");

    if (!file_M_C || !file_K_C) {
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }
// Ερώτημα (α)
    uint32_t M[2] = {0, 0}; // Μηνύματα αρχικά με μηδενική τιμή
    uint32_t C[2];
    uint32_t K[4] = {0, 0, 0, 0}; // Κλειδιά αρχικά με μηδενική τιμή

    //  Ζεύγη (M, C) για όλα τα M όταν K = 0
    uint32_t i;
    for(i = 0; i <= 0xFFFF; i++){
        M[0] = i; // Μόνο το πρώτο 16-bit αλλάζει
        C[0] = M[0];
        C[1] = M[1];
        TEA_encrypt(C, K);
        fprintf(file_M_C, "M: %08X %08X -> C: %08X %08X\n", M[0], M[1], C[0], C[1]);
    }

    // Ζεύγη (K, C) για όλα τα K όταν M = 0
    M[0] = 0;
    M[1] = 0;
    for (i = 0; i <= 0xFFFF; i++) {
        K[0] = i; // Μόνο το πρώτο 16-bit του κλειδιού αλλάζει
        C[0] = M[0];
        C[1] = M[1];
        TEA_encrypt(C, K);
        fprintf(file_K_C, "K: %08X %08X %08X %08X -> C: %08X %08X\n", K[0], K[1], K[2], K[3], C[0], C[1]);
    }
// Ερώτημα (β)
    //  Υπολογισμός υποκλειδιών για το K = a1e9
    uint32_t subkeys[4];
    generate_subkeys(0xA1E9, subkeys);

    printf("Generated subkeys:\n");
    for (int i = 0; i < 4; i++) {
        printf("k%d = %04X\n", i + 1, subkeys[i]);
    }

    fclose(file_M_C);
    fclose(file_K_C);

//  Ερώτημα (γ)
    // Μέτρηση απόδοσης για 2^26 μηνύματα
    printf("Measuring performance...\n");
    measure_performance(subkeys, 1 << 26);

    printf("Generated test vectors successfully.\n");
    return 0;
    return 0;
}


// Συναρτήσεις ερωτήματος (α)
    // Συνάρτηση κρυπτογράφησης
void TEA_encrypt(uint32_t *v, uint32_t *k){
    int i = 0;
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t sum = 0;

    for(i = 0; i < ROUNDS; i++){
        sum += DELTA;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }

    v[0] = v0;
    v[1] = v1;

    return;
}

    // Συνάρτηση αποκρυπτογράφησης
void TEA_decrypt(uint32_t *v, uint32_t *k) {
    int i;
    uint32_t v0 = v[0]; // Το πρώτο μισό του μηνύματος
    uint32_t v1 = v[1]; // Το δεύτερο μισό του μηνύματος
    uint32_t sum = DELTA * ROUNDS; // Αρχική τιμή για τη sum

    // 
    for(i = 0; i < ROUNDS; i++){
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= DELTA;
    }

    v[0] = v0;
    v[1] = v1;

    return;
}

// Συνάρτηση ερωτήματος (β)
void generate_subkeys(uint32_t initial_key, uint32_t *subkeys){
    uint32_t key = initial_key;
    int i;

    for(i = 0; i < 4; i++){
        key = (key << 2) | (key >> (16 - 2));   // Κυκλική ολίσθηση 2 bit
        subkeys[i] = key & 0xFFFF;  // Κρατάμε μόνο τα 16 bit
    }
    return;
}


// Συνάρτηση ερωτήματος (γ)
void measure_performance(uint32_t* key, size_t num_messages) {
    uint32_t *messages = malloc(num_messages * 2 * sizeof(uint32_t));
    if (!messages) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Γέμισμα με τυχαία δεδομένα
    for (size_t i = 0; i < num_messages * 2; i++) {
        messages[i] = rand();
    }
    
    clock_t start, end;
    size_t i;
// Μέτρηση χρόνου κρυπτογράφησης
    start = clock();
    for (i = 0; i < num_messages; i++) {
        TEA_encrypt(&messages[i * 2], key);
    }
    end = clock();
    double encryption_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    // Μέτρηση χρόνου αποκρυπτογράφησης
    start = clock();
    for (i = 0; i < num_messages; i++) {
        TEA_decrypt(&messages[i * 2], key);
    }
    end = clock();
    double decryption_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("Encryption time: %.6f seconds\n", encryption_time);
    printf("Decryption time: %.6f seconds\n", decryption_time);

    free(messages);
}
