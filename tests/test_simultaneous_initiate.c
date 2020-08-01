#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>

#include "../src/signal_protocol.h"
#include "curve.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "protocol.h"
#include "test_common.h"
#include "../src/curve25519/ed25519/ge.h"
#include "../src/key_helper.h"
#include "../src/curve25519/ed25519/additions/crypto_additions.h"
#include "../src/curve25519/ed25519/additions/generalized/ge_p3_add.c"
#include "curve25519/ed25519/ge_frombytes.c"
#include "curve25519/ed25519/ge_tobytes.c"


#define DJB_KEY_LEN 32
#define GE_128_LEN 128

#define integrated_ECElg


static signal_protocol_address alice_address = {
        "+14159998888", 12, 1
};

static signal_protocol_address bob_address = {
        "+14151231234", 12, 1
};

signal_context *global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

ec_key_pair *alice_signed_pre_key;
ec_key_pair *bob_signed_pre_key;
int32_t alice_signed_pre_key_id;
int32_t bob_signed_pre_key_id;

int is_session_id_equal(signal_protocol_store_context *alice_store, signal_protocol_store_context *bob_store);
int current_session_version(signal_protocol_store_context *store, const signal_protocol_address *address);
session_pre_key_bundle *create_alice_pre_key_bundle(signal_protocol_store_context *store);
session_pre_key_bundle *create_bob_pre_key_bundle(signal_protocol_store_context *store);

void test_lock(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void test_unlock(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

typedef struct {
    uint8_t private_key[DJB_KEY_LEN];
    ge_p3 *public_key;
} ecelg_key_pair;

typedef struct {
    ge_p3 *c1;
    ge_p3 *c2;
} ecelg_ciphertext;

ecelg_key_pair *alice_ecelg_key_pair;
ecelg_key_pair *bob_ecelg_key_pair;

void ecelg_generate_key_pair(signal_context *context, ecelg_key_pair **key_pair) {
    // pick private_key at random from {1, ..., q-1}
    ec_key_pair *x;
    int result;
    result = curve_generate_key_pair(context, &x);
    ck_assert_int_eq(result, 0);
    if (result!=0) {
        printf("Failed to generate ECElg keypair!\n");
    } else {
        *key_pair = malloc(sizeof(ecelg_key_pair));
        (*key_pair)->public_key = malloc(sizeof(ge_p3));
        memcpy((*key_pair)->private_key, get_private_data(ec_key_pair_get_private(x)), DJB_KEY_LEN);
    }
    SIGNAL_UNREF(x);
    // set public_key=g^x
    ge_scalarmult_base((*key_pair)->public_key, (*key_pair)->private_key);
    ck_assert((*key_pair)->public_key);
    ck_assert((*key_pair)->private_key);
}

void test_setup()
{
    int result;

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    result = signal_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    signal_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);

    result = signal_context_set_locking_functions(global_context, test_lock, test_unlock);
    ck_assert_int_eq(result, 0);

    result = curve_generate_key_pair(global_context, &alice_signed_pre_key);
    ck_assert_int_eq(result, 0);

    result = curve_generate_key_pair(global_context, &bob_signed_pre_key);
    ck_assert_int_eq(result, 0);

    alice_signed_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;
    bob_signed_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    // Generate key pairs for ECElg scheme:
    ecelg_generate_key_pair(global_context, &alice_ecelg_key_pair);
    ecelg_generate_key_pair(global_context, &bob_ecelg_key_pair);
}

void test_teardown()
{
    SIGNAL_UNREF(alice_signed_pre_key);
    SIGNAL_UNREF(bob_signed_pre_key);
    signal_context_destroy(global_context);
    free(bob_ecelg_key_pair->public_key);
    free(bob_ecelg_key_pair);
    free(alice_ecelg_key_pair->public_key);
    free(alice_ecelg_key_pair);
    
    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}

START_TEST(test_basic_simultaneous_initiate)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages */
    static const char message_for_bob_data[] = "hey there";
    size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
    ciphertext_message *message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)message_for_bob_data, message_for_bob_len,
            &message_for_bob);
    ck_assert_int_eq(result, 0);

    static const char message_for_alice_data[] = "sample message";
    size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
    ciphertext_message *message_for_alice = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)message_for_alice_data, message_for_alice_len,
            &message_for_alice);
    ck_assert_int_eq(result, 0);

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Copy the messages before decrypting */
    pre_key_signal_message *message_for_alice_copy = 0;
    result = pre_key_signal_message_copy(&message_for_alice_copy,
            (pre_key_signal_message *)message_for_alice, global_context);
    ck_assert_int_eq(result, 0);

    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the messages */
    signal_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the messages decrypted correctly */
    uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
    ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(alice_plaintext);
    signal_buffer_free(bob_plaintext);
    SIGNAL_UNREF(message_for_alice_copy);
    SIGNAL_UNREF(message_for_bob_copy);
    SIGNAL_UNREF(message_for_alice);
    SIGNAL_UNREF(message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    SIGNAL_UNREF(alice_pre_key_bundle);
    SIGNAL_UNREF(bob_pre_key_bundle);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_lost_simultaneous_initiate)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages */
    static const char message_for_bob_data[] = "hey there";
    size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
    ciphertext_message *message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)message_for_bob_data, message_for_bob_len,
            &message_for_bob);
    ck_assert_int_eq(result, 0);

    static const char message_for_alice_data[] = "sample message";
    size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
    ciphertext_message *message_for_alice = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)message_for_alice_data, message_for_alice_len,
            &message_for_alice);
    ck_assert_int_eq(result, 0);

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Copy the message for Bob before decrypting */
    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the message */
    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Verify that the session version is correct */
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_PREKEY_TYPE);

    /* Copy the message before decrypting */
    pre_key_signal_message *alice_response_copy = 0;
    result = pre_key_signal_message_copy(&alice_response_copy,
            (pre_key_signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(bob_plaintext);
    SIGNAL_UNREF(message_for_bob_copy);
    SIGNAL_UNREF(message_for_alice);
    SIGNAL_UNREF(message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    SIGNAL_UNREF(alice_pre_key_bundle);
    SIGNAL_UNREF(bob_pre_key_bundle);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_simultaneous_initiate_lost_message)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages */
    static const char message_for_bob_data[] = "hey there";
    size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
    ciphertext_message *message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)message_for_bob_data, message_for_bob_len,
            &message_for_bob);
    ck_assert_int_eq(result, 0);

    static const char message_for_alice_data[] = "sample message";
    size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
    ciphertext_message *message_for_alice = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)message_for_alice_data, message_for_alice_len,
            &message_for_alice);
    ck_assert_int_eq(result, 0);

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Copy the messages before decrypting */
    pre_key_signal_message *message_for_alice_copy = 0;
    result = pre_key_signal_message_copy(&message_for_alice_copy,
            (pre_key_signal_message *)message_for_alice, global_context);
    ck_assert_int_eq(result, 0);

    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the messages */
    signal_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the messages decrypted correctly */
    uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
    ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /*
     * Intentionally skip Bob decrypting the response, and continue
     * with the rest of the test.
     */

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(alice_plaintext);
    signal_buffer_free(bob_plaintext);
    SIGNAL_UNREF(message_for_alice_copy);
    SIGNAL_UNREF(message_for_bob_copy);
    SIGNAL_UNREF(message_for_alice);
    SIGNAL_UNREF(message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    SIGNAL_UNREF(alice_pre_key_bundle);
    SIGNAL_UNREF(bob_pre_key_bundle);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_simultaneous_initiate_repeated_messages)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages */
    static const char message_for_bob_data[] = "hey there";
    size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
    ciphertext_message *message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)message_for_bob_data, message_for_bob_len,
            &message_for_bob);
    ck_assert_int_eq(result, 0);

    static const char message_for_alice_data[] = "sample message";
    size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
    ciphertext_message *message_for_alice = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)message_for_alice_data, message_for_alice_len,
            &message_for_alice);
    ck_assert_int_eq(result, 0);

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Copy the messages before decrypting */
    pre_key_signal_message *message_for_alice_copy = 0;
    result = pre_key_signal_message_copy(&message_for_alice_copy,
            (pre_key_signal_message *)message_for_alice, global_context);
    ck_assert_int_eq(result, 0);

    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the messages */
    signal_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the messages decrypted correctly */
    uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
    ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    int i;
    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(alice_plaintext);
    signal_buffer_free(bob_plaintext);
    SIGNAL_UNREF(message_for_alice_copy);
    SIGNAL_UNREF(message_for_bob_copy);
    SIGNAL_UNREF(message_for_alice);
    SIGNAL_UNREF(message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    SIGNAL_UNREF(alice_pre_key_bundle);
    SIGNAL_UNREF(bob_pre_key_bundle);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_repeated_simultaneous_initiate_repeated_messages)
{
    int result = 0;
    int i;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    for(i = 0; i < 15; i++) {
        /* Create the pre key bundles */
        session_pre_key_bundle *alice_pre_key_bundle =
                create_alice_pre_key_bundle(alice_store);
        session_pre_key_bundle *bob_pre_key_bundle =
                create_bob_pre_key_bundle(bob_store);

        /* Process the pre key bundles */
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
        ck_assert_int_eq(result, 0);

        result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
        ck_assert_int_eq(result, 0);

        /* Encrypt a pair of messages */
        static const char message_for_bob_data[] = "hey there";
        size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
        ciphertext_message *message_for_bob = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_data, message_for_bob_len,
                &message_for_bob);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_data[] = "sample message";
        size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
        ciphertext_message *message_for_alice = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_data, message_for_alice_len,
                &message_for_alice);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        pre_key_signal_message *message_for_alice_copy = 0;
        result = pre_key_signal_message_copy(&message_for_alice_copy,
                (pre_key_signal_message *)message_for_alice, global_context);
        ck_assert_int_eq(result, 0);

        pre_key_signal_message *message_for_bob_copy = 0;
        result = pre_key_signal_message_copy(&message_for_bob_copy,
                (pre_key_signal_message *)message_for_bob, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
        size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
        ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

        uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
        size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
        ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

        /* Verify that the session versions are correct and the IDs are not equal */
        ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
        ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(alice_plaintext);
        signal_buffer_free(bob_plaintext);
        SIGNAL_UNREF(message_for_alice_copy);
        SIGNAL_UNREF(message_for_bob_copy);
        SIGNAL_UNREF(message_for_alice);
        SIGNAL_UNREF(message_for_bob);
        SIGNAL_UNREF(alice_pre_key_bundle);
        SIGNAL_UNREF(bob_pre_key_bundle);
    }

    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_repeated_simultaneous_initiate_lost_message_repeated_messages)
{
    int result = 0;
    int i;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the pre key bundles, intentionally skipping Alice's */
    session_pre_key_bundle *bob_lost_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Process the pre key bundles, intentionally skipping Alice's */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_lost_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages, intentionally skipping Alice's */
    static const char lost_message_for_bob_data[] = "hey there";
    size_t lost_message_for_bob_len = sizeof(lost_message_for_bob_data) - 1;
    ciphertext_message *lost_message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)lost_message_for_bob_data, lost_message_for_bob_len,
            &lost_message_for_bob);
    ck_assert_int_eq(result, 0);

    for(i = 0; i < 15; i++) {
        /* Create the pre key bundles */
        session_pre_key_bundle *alice_pre_key_bundle =
                create_alice_pre_key_bundle(alice_store);
        session_pre_key_bundle *bob_pre_key_bundle =
                create_bob_pre_key_bundle(bob_store);

        /* Process the pre key bundles */
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
        ck_assert_int_eq(result, 0);

        result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
        ck_assert_int_eq(result, 0);

        /* Encrypt a pair of messages */
        static const char message_for_bob_data[] = "hey there";
        size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
        ciphertext_message *message_for_bob = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_data, message_for_bob_len,
                &message_for_bob);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_data[] = "sample message";
        size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
        ciphertext_message *message_for_alice = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_data, message_for_alice_len,
                &message_for_alice);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        pre_key_signal_message *message_for_alice_copy = 0;
        result = pre_key_signal_message_copy(&message_for_alice_copy,
                (pre_key_signal_message *)message_for_alice, global_context);
        ck_assert_int_eq(result, 0);

        pre_key_signal_message *message_for_bob_copy = 0;
        result = pre_key_signal_message_copy(&message_for_bob_copy,
                (pre_key_signal_message *)message_for_bob, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
        size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
        ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

        uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
        size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
        ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

        /* Verify that the session versions are correct and the IDs are not equal */
        ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
        ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(alice_plaintext);
        signal_buffer_free(bob_plaintext);
        SIGNAL_UNREF(message_for_alice_copy);
        SIGNAL_UNREF(message_for_bob_copy);
        SIGNAL_UNREF(message_for_alice);
        SIGNAL_UNREF(message_for_bob);
        SIGNAL_UNREF(alice_pre_key_bundle);
        SIGNAL_UNREF(bob_pre_key_bundle);
    }

    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Copy the lost message before decrypting */
    pre_key_signal_message *lost_message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&lost_message_for_bob_copy,
            (pre_key_signal_message *)lost_message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the lost message */
    signal_buffer *lost_message_for_bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher,
            lost_message_for_bob_copy, 0, &lost_message_for_bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the lost message decrypted correctly */
    uint8_t *lost_bob_plaintext_data = signal_buffer_data(lost_message_for_bob_plaintext);
    size_t lost_bob_plaintext_len = signal_buffer_len(lost_message_for_bob_plaintext);
    ck_assert_int_eq(lost_message_for_bob_len, lost_bob_plaintext_len);
    ck_assert_int_eq(memcmp(lost_message_for_bob_data, lost_bob_plaintext_data, lost_bob_plaintext_len), 0);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Encrypt an unexpected final message */
    static const char blast_from_the_past_data[] = "unexpected!";
    size_t blast_from_the_past_len = sizeof(blast_from_the_past_data) - 1;
    ciphertext_message *blast_from_the_past = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)blast_from_the_past_data, blast_from_the_past_len,
            &blast_from_the_past);
    ck_assert_int_eq(result, 0);

    /* Copy the unexpected message before decrypting */
    signal_message *blast_from_the_past_copy = 0;
    result = signal_message_copy(&blast_from_the_past_copy,
            (signal_message *)blast_from_the_past, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the unexpected message */
    signal_buffer *blast_from_the_past_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher,
            blast_from_the_past_copy, 0, &blast_from_the_past_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the unexpected message decrypted correctly */
    uint8_t *blast_from_the_past_decrypted_data = signal_buffer_data(blast_from_the_past_plaintext);
    size_t blast_from_the_past_decrypted_len = signal_buffer_len(blast_from_the_past_plaintext);
    ck_assert_int_eq(blast_from_the_past_len, blast_from_the_past_decrypted_len);
    ck_assert_int_eq(memcmp(blast_from_the_past_data, blast_from_the_past_decrypted_data, blast_from_the_past_decrypted_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(blast_from_the_past_plaintext);
    SIGNAL_UNREF(blast_from_the_past_copy);
    SIGNAL_UNREF(blast_from_the_past);
    signal_buffer_free(lost_message_for_bob_plaintext);
    SIGNAL_UNREF(lost_message_for_bob_copy);
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    SIGNAL_UNREF(bob_lost_pre_key_bundle);
    SIGNAL_UNREF(lost_message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

void ecelg_generate_secret(ge_p3 *secret, signal_context *context) {
    uint8_t *exponent = malloc(DJB_KEY_LEN);
    int result = signal_protocol_key_helper_generate_exponent(&exponent, context);
    ck_assert_int_eq(result, 0); 
    ge_scalarmult_base(secret, exponent);
}

void ecelg_encrypt(ecelg_ciphertext **ciphertext, ge_p3* message, ge_p3 *their_public_key, uint8_t *our_private_key)
{
    // Set the shared secret to S=h^y=g^(xy)
    ge_p3 Sfull;
    ge_scalarmult(&Sfull, our_private_key, their_public_key);
    // Set c1=g^y
    *ciphertext = malloc(sizeof(ecelg_ciphertext));
    (*ciphertext)->c1 = malloc(sizeof(ge_p3));
    ge_scalarmult_base((*ciphertext)->c1, our_private_key);
    // Set c2=message*S
    (*ciphertext)->c2 = malloc(sizeof(ge_p3));
    ge_p3_add((*ciphertext)->c2, message, &Sfull);
    // Now ciphertext is c=(c1, c2)
}

void ecelg_decrypt(ge_p3 *plaintext, ecelg_ciphertext *ciphertext, uint8_t *our_private_key)
{
    // Retrieve the shared secret S=c1^x=g^(xy)
    ge_p3 Sfull;
    ge_scalarmult(&Sfull, our_private_key, ciphertext->c1);
    // Compute S^(-1)
    ge_p3 Sfull_neg;
    ge_neg(&Sfull_neg, &Sfull);
    // Plaintext p = c2*S^(-1)
    ge_p3_add(plaintext, ciphertext->c2, &Sfull_neg);
}

/* returns 1 if pre = post, 0 otherwise */
int ecelg_compare(const ge_p3 *pre, const ge_p3 *post) {
    ge_p1p1 control_p1p1;
    ge_cached pre_cached;
    ge_p3_to_cached(&pre_cached, pre);
    ge_sub(&control_p1p1, post, &pre_cached);
    ge_p3 control_p3;
    ge_p1p1_to_p3(&control_p3, &control_p1p1);
    return ge_isneutral(&control_p3);
}

START_TEST(test_ec_elg_scheme)
{
    printf("\nStarting test_ec_elg_scheme...\n");
    int result = 0;
    
    /* Alice creates kA */
    ge_p3 kA;
    ecelg_generate_secret(&kA, global_context);  

    /* Bob creates kB */
    ge_p3 kB;
    ecelg_generate_secret(&kB, global_context);
    
    /* Alice encrypts kA with Bob's public key resulting in cA */
    ecelg_ciphertext *cA;
    ecelg_encrypt(&cA, &kA, bob_ecelg_key_pair->public_key, alice_ecelg_key_pair->private_key);

    /* Bob encrypts kB with Alice's public key resulting in cB */
    ecelg_ciphertext *cB;
    ecelg_encrypt(&cB, &kB, alice_ecelg_key_pair->public_key, bob_ecelg_key_pair->private_key);

    /* Bob decrypts cA */
    ge_p3 plaintext_kA;
    ecelg_decrypt(&plaintext_kA, cA, bob_ecelg_key_pair->private_key);

    /* Alice decrypts cB */
    ge_p3 plaintext_kB;
    ecelg_decrypt(&plaintext_kB, cB, alice_ecelg_key_pair->private_key);

    /* Check the decryption of cA */
    result = ecelg_compare(&kA, &plaintext_kA);
    if (result!=1) {
        printf("[FAILURE] Decryption failed!\n");
    } else printf("[SUCCESS] Decryption passed.\n"); 

    /* Check the decryption of cB */
    result = ecelg_compare(&kB, &plaintext_kB);
    if (result!=1) {
        printf("[FAILURE] Decryption failed!\n");
    } else printf("[SUCCESS] Decryption passed.\n"); 

    /* Cleanup */
    free(cA->c1);
    free(cA->c2);
    free(cA);
    free(cB->c1);
    free(cB->c2);
    free(cB);
}
END_TEST

#ifdef integrated_ECElg

START_TEST(test_integrated_ec_elg_scheme)
{
    printf("\nStarting test_integrated_ec_elg_scheme...\n");
    int result = 0;
    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);
    
    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);
    
    /* Alice creates kA */
    ge_p3 kA;
    ecelg_generate_secret(&kA, global_context);  

    /* Bob creates kB */
    ge_p3 kB;
    ecelg_generate_secret(&kB, global_context);
    
    /* Alice encrypts kA with Bob's public key resulting in cA */
    ecelg_ciphertext *cA;
    ecelg_encrypt(&cA, &kA, bob_ecelg_key_pair->public_key, alice_ecelg_key_pair->private_key);

    /* Bob encrypts kB with Alice's public key resulting in cB */
    ecelg_ciphertext *cB;
    ecelg_encrypt(&cB, &kB, alice_ecelg_key_pair->public_key, bob_ecelg_key_pair->private_key);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);
    
    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle);
    ck_assert_int_eq(result, 0);

    /* Prepare the ciphertext to be sent as a signal message */
    uint8_t cA_part1 [GE_128_LEN];
    ge_p3_tobytes_128(cA_part1, cA->c1);
    uint8_t cA_part2 [GE_128_LEN];
    ge_p3_tobytes_128(cA_part2, cA->c2);
    uint8_t message_for_bob_data [2*GE_128_LEN];
    memcpy(message_for_bob_data, cA_part1, GE_128_LEN);
    memcpy(message_for_bob_data + GE_128_LEN, cA_part2, GE_128_LEN);

    uint8_t cB_part1 [GE_128_LEN];
    ge_p3_tobytes_128(cB_part1, cB->c1);
    uint8_t cB_part2 [GE_128_LEN];
    ge_p3_tobytes_128(cB_part2, cB->c2);
    uint8_t message_for_alice_data [2*GE_128_LEN];
    memcpy(message_for_alice_data, cB_part1, GE_128_LEN);
    memcpy(message_for_alice_data + GE_128_LEN, cB_part2, GE_128_LEN);

    /* Encrypt a pair of messages */
    size_t message_for_bob_len = sizeof(message_for_bob_data);
    ciphertext_message *message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)message_for_bob_data, message_for_bob_len,
            &message_for_bob);
    ck_assert_int_eq(result, 0);

    size_t message_for_alice_len = sizeof(message_for_alice_data);
    ciphertext_message *message_for_alice = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)message_for_alice_data, message_for_alice_len,
            &message_for_alice);
    ck_assert_int_eq(result, 0);

    /* Copy the messages before decrypting */
    pre_key_signal_message *message_for_alice_copy = 0;
    result = pre_key_signal_message_copy(&message_for_alice_copy,
            (pre_key_signal_message *)message_for_alice, global_context);
    ck_assert_int_eq(result, 0);

    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the messages */
    signal_buffer *alice_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the messages decrypted correctly */
    uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
    size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
    ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Read the signal message back into ecelg_ciphertext */
    uint8_t bob_plaintext_part1 [GE_128_LEN];
    uint8_t bob_plaintext_part2 [GE_128_LEN];
    memcpy(bob_plaintext_part1, bob_plaintext_data, GE_128_LEN);
    memcpy(bob_plaintext_part2, bob_plaintext_data + GE_128_LEN, GE_128_LEN);
    ge_p3 *bob_plaintext_c1 = malloc(sizeof(ge_p3));
    ge_p3 *bob_plaintext_c2 = malloc(sizeof(ge_p3));
    ge_frombytes_128(bob_plaintext_c1, bob_plaintext_part1);
    ge_frombytes_128(bob_plaintext_c2, bob_plaintext_part2);
    ecelg_ciphertext *plaintext_cA = malloc(sizeof(ecelg_ciphertext));
    plaintext_cA->c1 = bob_plaintext_c1;
    plaintext_cA->c2 = bob_plaintext_c2;

    uint8_t alice_plaintext_part1 [GE_128_LEN];
    uint8_t alice_plaintext_part2 [GE_128_LEN];
    memcpy(alice_plaintext_part1, alice_plaintext_data, GE_128_LEN);
    memcpy(alice_plaintext_part2, alice_plaintext_data + GE_128_LEN, GE_128_LEN);
    ge_p3 *alice_plaintext_c1 = malloc(sizeof(ge_p3));
    ge_p3 *alice_plaintext_c2 = malloc(sizeof(ge_p3));
    ge_frombytes_128(alice_plaintext_c1, alice_plaintext_part1);
    ge_frombytes_128(alice_plaintext_c2, alice_plaintext_part2);
    ecelg_ciphertext *plaintext_cB = malloc(sizeof(ecelg_ciphertext));
    plaintext_cB->c1 = alice_plaintext_c1;
    plaintext_cB->c2 = alice_plaintext_c2;

    /* Check that the ciphertexts were read correctly */
   
    result = ecelg_compare(cA->c1, plaintext_cA->c1);
    ck_assert_int_eq(result, 1);
    result = ecelg_compare(cA->c2, plaintext_cA->c2);
    ck_assert_int_eq(result, 1);
    result = ecelg_compare(cB->c1, plaintext_cB->c1);
    ck_assert_int_eq(result, 1);
    result = ecelg_compare(cB->c2, plaintext_cB->c2);
    ck_assert_int_eq(result, 1);

    /* Bob decrypts cA */
    ge_p3 plaintext_kA;
    ecelg_decrypt(&plaintext_kA, plaintext_cA, bob_ecelg_key_pair->private_key);

    /* Alice decrypts cB */
    ge_p3 plaintext_kB;
    ecelg_decrypt(&plaintext_kB, plaintext_cB, alice_ecelg_key_pair->private_key);

    /* Check the decryption of cA */
    result = ecelg_compare(&kA, &plaintext_kA);
    ck_assert_int_eq(result, 1);
    if (result!=1) {
        printf("[FAILURE] Decryption failed!\n");
    } else printf("[SUCCESS] Decryption passed.\n"); 

    /* Check the decryption of cB */
    result = ecelg_compare(&kB, &plaintext_kB);
    ck_assert_int_eq(result, 1);
    if (result!=1) {
        printf("[FAILURE] Decryption failed!\n");
    } else printf("[SUCCESS] Decryption passed.\n"); 

    /* TODO: for the session cipher, concatenate and hash the shared key as (kA||kB||g^xy) same way as before 
    * Steps: 
    * 1. Follow the steps as before to alter the session builder, cipher_decrypt functions and include kA and kB as parameters
    * 2. Alter the code to account for the difference in the kA/kB types (i.e. it was uint8_t [32], now it is ecelg_ciphertext)
    * 3. Test the new scheme
    */

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the message before decrypting */
    signal_message *alice_response_copy = 0;
    result = signal_message_copy(&alice_response_copy,
            (signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Prepare Bob's final message */
    static const char final_message_data[] = "third message";
    size_t final_message_len = sizeof(final_message_data) - 1;
    ciphertext_message *final_message = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)final_message_data, final_message_len,
            &final_message);
    ck_assert_int_eq(result, 0);

    /* Verify final message type */
    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

    /* Copy the final message before decrypting */
    signal_message *final_message_copy = 0;
    result = signal_message_copy(&final_message_copy,
            (signal_message *)final_message, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Alice decrypt the final message */
    signal_buffer *final_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the final message decrypted correctly */
    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
    ck_assert_int_eq(final_message_len, final_plaintext_len);
    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);


    /* Cleanup */
    free(cA->c1);
    free(cA->c2);
    free(cA);
    free(cB->c1);
    free(cB->c2);
    free(cB);
    free(plaintext_cA->c1);
    free(plaintext_cA);
    free(plaintext_cB->c1);
    free(plaintext_cB);
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(alice_plaintext);
    signal_buffer_free(bob_plaintext);
    SIGNAL_UNREF(message_for_alice_copy);
    SIGNAL_UNREF(message_for_bob_copy);
    SIGNAL_UNREF(message_for_alice);
    SIGNAL_UNREF(message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    SIGNAL_UNREF(alice_pre_key_bundle);
    SIGNAL_UNREF(bob_pre_key_bundle);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}

#endif

END_TEST

int is_session_id_equal(signal_protocol_store_context *alice_store, signal_protocol_store_context *bob_store)
{
    int result = 0;
    session_record *alice_store_record = 0;
    session_record *bob_store_record = 0;
    ec_public_key *alice_store_alice_base_key = 0;
    ec_public_key *bob_store_alice_base_key = 0;

    result = signal_protocol_session_load_session(alice_store, &alice_store_record, &bob_address);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_session_load_session(bob_store, &bob_store_record, &alice_address);
    ck_assert_int_eq(result, 0);

    alice_store_alice_base_key =
            session_state_get_alice_base_key(session_record_get_state(alice_store_record));
    bob_store_alice_base_key =
            session_state_get_alice_base_key(session_record_get_state(bob_store_record));

    if(ec_public_key_compare(alice_store_alice_base_key, bob_store_alice_base_key) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    SIGNAL_UNREF(alice_store_record);
    SIGNAL_UNREF(bob_store_record);
    return result;
}

int current_session_version(signal_protocol_store_context *store, const signal_protocol_address *address)
{
    int result = 0;
    session_record *record = 0;
    session_state *state = 0;

    result = signal_protocol_session_load_session(store, &record, address);
    ck_assert_int_eq(result, 0);

    state = session_record_get_state(record);

    result = session_state_get_session_version(state);

    SIGNAL_UNREF(record);

    return result;
}

session_pre_key_bundle *create_alice_pre_key_bundle(signal_protocol_store_context *store)
{
    int result = 0;

    ec_key_pair *alice_unsigned_pre_key = 0;
    curve_generate_key_pair(global_context, &alice_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    int alice_unsigned_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    ratchet_identity_key_pair *alice_identity_key_pair = 0;
    result = signal_protocol_identity_get_key_pair(store, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ec_public_key *alice_signed_pre_key_public = ec_key_pair_get_public(alice_signed_pre_key);

    signal_buffer *alice_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&alice_signed_pre_key_public_serialized, alice_signed_pre_key_public);
    ck_assert_int_eq(result, 0);

    signal_buffer *signature = 0;
    result = curve_calculate_signature(global_context, &signature,
            ratchet_identity_key_pair_get_private(alice_identity_key_pair),
            signal_buffer_data(alice_signed_pre_key_public_serialized),
            signal_buffer_len(alice_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *alice_pre_key_bundle = 0;
    result = session_pre_key_bundle_create(&alice_pre_key_bundle,
            1, 1,
            alice_unsigned_pre_key_id,
            ec_key_pair_get_public(alice_unsigned_pre_key),
            alice_signed_pre_key_id, alice_signed_pre_key_public,
            signal_buffer_data(signature), signal_buffer_len(signature),
            ratchet_identity_key_pair_get_public(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&signed_pre_key_record,
            alice_signed_pre_key_id, time(0), alice_signed_pre_key,
            signal_buffer_data(signature), signal_buffer_len(signature));
    ck_assert_int_eq(result, 0);

    result = signal_protocol_signed_pre_key_store_key(store, signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_pre_key *pre_key_record = 0;
    result = session_pre_key_create(&pre_key_record, alice_unsigned_pre_key_id, alice_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_pre_key_store_key(store, pre_key_record);
    ck_assert_int_eq(result, 0);

    SIGNAL_UNREF(pre_key_record);
    SIGNAL_UNREF(signed_pre_key_record);
    SIGNAL_UNREF(alice_identity_key_pair);
    SIGNAL_UNREF(alice_unsigned_pre_key);
    signal_buffer_free(alice_signed_pre_key_public_serialized);
    signal_buffer_free(signature);

    return alice_pre_key_bundle;
}

session_pre_key_bundle *create_bob_pre_key_bundle(signal_protocol_store_context *store)
{
    int result = 0;

    ec_key_pair *bob_unsigned_pre_key = 0;
    curve_generate_key_pair(global_context, &bob_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    int bob_unsigned_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = signal_protocol_identity_get_key_pair(store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ec_public_key *bob_signed_pre_key_public = ec_key_pair_get_public(bob_signed_pre_key);

    signal_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized, bob_signed_pre_key_public);
    ck_assert_int_eq(result, 0);

    signal_buffer *signature = 0;
    result = curve_calculate_signature(global_context, &signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            signal_buffer_data(bob_signed_pre_key_public_serialized),
            signal_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key_bundle = 0;
    result = session_pre_key_bundle_create(&bob_pre_key_bundle,
            1, 1,
            bob_unsigned_pre_key_id,
            ec_key_pair_get_public(bob_unsigned_pre_key),
            bob_signed_pre_key_id, bob_signed_pre_key_public,
            signal_buffer_data(signature), signal_buffer_len(signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&signed_pre_key_record,
            bob_signed_pre_key_id, time(0), bob_signed_pre_key,
            signal_buffer_data(signature), signal_buffer_len(signature));
    ck_assert_int_eq(result, 0);

    result = signal_protocol_signed_pre_key_store_key(store, signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_pre_key *pre_key_record = 0;
    result = session_pre_key_create(&pre_key_record, bob_unsigned_pre_key_id, bob_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_pre_key_store_key(store, pre_key_record);
    ck_assert_int_eq(result, 0);

    SIGNAL_UNREF(pre_key_record);
    SIGNAL_UNREF(signed_pre_key_record);
    SIGNAL_UNREF(bob_identity_key_pair);
    SIGNAL_UNREF(bob_unsigned_pre_key);
    signal_buffer_free(bob_signed_pre_key_public_serialized);
    signal_buffer_free(signature);

    return bob_pre_key_bundle;
}

Suite *simultaneous_initiate_suite(void)
{
    Suite *suite = suite_create("simultaneous_initiate");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_basic_simultaneous_initiate);
    tcase_add_test(tcase, test_lost_simultaneous_initiate);
    tcase_add_test(tcase, test_simultaneous_initiate_lost_message);
    tcase_add_test(tcase, test_simultaneous_initiate_repeated_messages);
    tcase_add_test(tcase, test_repeated_simultaneous_initiate_repeated_messages);
    tcase_add_test(tcase, test_repeated_simultaneous_initiate_lost_message_repeated_messages);
    tcase_add_test(tcase, test_ec_elg_scheme);
    tcase_add_test(tcase, test_integrated_ec_elg_scheme);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = simultaneous_initiate_suite();
    runner = srunner_create(suite);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
