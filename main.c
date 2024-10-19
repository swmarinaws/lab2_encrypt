/**
 * @file main.c
 * @brief Программа для шифрования и расшифрования файлов с использованием GTK и OpenSSL.
 *
 * Данная программа предоставляет интерфейс для шифрования и расшифрования файлов.
 * Пользователь может выбрать файл для шифрования/расшифрования, а также ввести пароль для защиты данных.
 */

#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

#define SALT_SIZE 16 /**< Размер соли (в байтах). */
#define KEY_SIZE 32  /**< Размер ключа (в байтах). */
#define IV_SIZE 16   /**< Размер вектора инициализации (IV) (в байтах). */

int encrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key, const unsigned char *iv);
int decrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key, const unsigned char *iv);

/**
 * @brief Структура для хранения виджетов интерфейса.
 */
typedef struct {
    GtkWidget *entry;/**< Поле для ввода пароля. */
} AppWidgets;

/**
 * @brief Обработчик нажатия кнопки "Зашифровать".
 * 
 * Запускает процесс шифрования файла после ввода пароля и выбора входного и выходного файлов.
 *
 * @param widget Виджет кнопки.
 * @param data Данные приложения (структура AppWidgets).
 */
void on_encrypt_clicked(GtkWidget *widget, gpointer data) {
    AppWidgets *widgets = (AppWidgets *)data;
    const char *password = gtk_entry_get_text(GTK_ENTRY(widgets->entry));
    
    if (strlen(password) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Пароль не может быть пустым!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    // Диалог выбора входного файла
    GtkWidget *file_chooser = gtk_file_chooser_dialog_new("Выберите файл для шифрования",
                                                          NULL,
                                                          GTK_FILE_CHOOSER_ACTION_OPEN,
                                                          "_Отмена", GTK_RESPONSE_CANCEL,
                                                          "_Открыть", GTK_RESPONSE_ACCEPT,
                                                          NULL);
    char *in_filename = NULL;
    char *out_filename = NULL;
    if (gtk_dialog_run(GTK_DIALOG(file_chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
        in_filename = filename;
    }
    gtk_widget_destroy(file_chooser);

    if (in_filename == NULL) {
        return;
    }

    // Диалог выбора выходного файла
    GtkWidget *save_chooser = gtk_file_chooser_dialog_new("Сохранить зашифрованный файл",
                                                          NULL,
                                                          GTK_FILE_CHOOSER_ACTION_SAVE,
                                                          "_Отмена", GTK_RESPONSE_CANCEL,
                                                          "_Сохранить", GTK_RESPONSE_ACCEPT,
                                                          NULL);
    if (gtk_dialog_run(GTK_DIALOG(save_chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save_chooser));
        out_filename = filename;
    }
    gtk_widget_destroy(save_chooser);

    if (out_filename == NULL) {
        g_free(in_filename);
        return;
    }

    unsigned char key[KEY_SIZE], iv[IV_SIZE], salt[SALT_SIZE];

    // Генерация соли
    if (!RAND_bytes(salt, sizeof(salt))) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка генерации соли!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Генерация ключа из пароля
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(key), key)) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка генерации ключа из пароля!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Генерация IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка генерации IV!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Открытие выходного файла и запись соли и IV
    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Не удалось открыть выходной файл для записи!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }
    fwrite(salt, 1, SALT_SIZE, out_file);
    fwrite(iv, 1, IV_SIZE, out_file);
    fclose(out_file);

    // Шифрование файла
    if (encrypt_file(in_filename, out_filename, key, iv) != 0) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка шифрования файла!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    } else {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
                                                   "Файл успешно зашифрован!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }

    g_free(in_filename);
    g_free(out_filename);
}

/**
 * @brief Обработчик нажатия кнопки "Расшифровать".
 * 
 * Запускает процесс расшифрования файла после ввода пароля и выбора входного и выходного файлов.
 *
 * @param widget Виджет кнопки.
 * @param data Данные приложения (структура AppWidgets).
 */
void on_decrypt_clicked(GtkWidget *widget, gpointer data) {
    AppWidgets *widgets = (AppWidgets *)data;
    const char *password = gtk_entry_get_text(GTK_ENTRY(widgets->entry));

    if (strlen(password) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Пароль не может быть пустым!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    // Диалог выбора входного файла
    GtkWidget *file_chooser = gtk_file_chooser_dialog_new("Выберите файл для дешифрования",
                                                          NULL,
                                                          GTK_FILE_CHOOSER_ACTION_OPEN,
                                                          "_Отмена", GTK_RESPONSE_CANCEL,
                                                          "_Открыть", GTK_RESPONSE_ACCEPT,
                                                          NULL);
    char *in_filename = NULL;
    char *out_filename = NULL;
    if (gtk_dialog_run(GTK_DIALOG(file_chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
        in_filename = filename;
    }
    gtk_widget_destroy(file_chooser);

    if (in_filename == NULL) {
        return;
    }

    // Диалог выбора выходного файла
    GtkWidget *save_chooser = gtk_file_chooser_dialog_new("Сохранить расшифрованный файл",
                                                          NULL,
                                                          GTK_FILE_CHOOSER_ACTION_SAVE,
                                                          "_Отмена", GTK_RESPONSE_CANCEL,
                                                          "_Сохранить", GTK_RESPONSE_ACCEPT,
                                                          NULL);
    if (gtk_dialog_run(GTK_DIALOG(save_chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(save_chooser));
        out_filename = filename;
    }
    gtk_widget_destroy(save_chooser);

    if (out_filename == NULL) {
        g_free(in_filename);
        return;
    }

    unsigned char key[KEY_SIZE], iv[IV_SIZE], salt[SALT_SIZE];

    // Открытие входного файла
    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Не удалось открыть входной файл для чтения!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Чтение соли из файла
    if (fread(salt, 1, SALT_SIZE, in_file) != SALT_SIZE) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка чтения соли из файла!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        fclose(in_file);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Чтение IV из файла
    if (fread(iv, 1, IV_SIZE, in_file) != IV_SIZE) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка чтения IV из файла!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        fclose(in_file);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    fclose(in_file);

    // Генерация ключа из пароля и соли
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(key), key)) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка генерации ключа из пароля!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(in_filename);
        g_free(out_filename);
        return;
    }

    // Расшифрование файла
    if (decrypt_file(in_filename, out_filename, key, iv) != 0) {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
                                                   "Ошибка расшифрования файла! Возможно, неверный пароль.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    } else {
        GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
                                                   GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
                                                   "Файл успешно расшифрован!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }

    g_free(in_filename);
    g_free(out_filename);
}

/**
 * @brief Функция для шифрования файла.
 * 
 * Шифрует содержимое входного файла с использованием алгоритма AES-256-CBC. Сначала
 * генерируется соль и вектор инициализации (IV), которые сохраняются в выходной файл перед
 * самим зашифрованным содержимым. Ключ для шифрования генерируется из пароля с использованием 
 * функции PBKDF2 (Password-Based Key Derivation Function 2).
 *
 * Алгоритм:
 * 1. Чтение входного файла.
 * 2. Генерация соли и IV.
 * 3. Генерация ключа на основе пароля.
 * 4. Шифрование содержимого и запись в выходной файл.
 *
 * @param in_filename Имя входного файла.
 * @param out_filename Имя выходного файла.
 * @param key Ключ для шифрования (должен быть длиной 32 байта для AES-256).
 * @param iv Вектор инициализации (должен быть длиной 16 байт для AES-256).
 * @return 0 при успешном шифровании, -1 в случае ошибки.
 */
int encrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key, const unsigned char *iv) {
    FILE *in_file = fopen(in_filename, "rb");
    FILE *out_file = fopen(out_filename, "aw"); // Добавляем к уже записанным salt и iv
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char buffer[1024];
    unsigned char out_buffer[1040];
    int len, out_len;

    if (!in_file || !out_file || !ctx) {
        if (in_file) fclose(in_file);
        if (out_file) fclose(out_file);
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return -1;
    }

    while ((len = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buffer, &out_len, buffer, len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_file);
            fclose(out_file);
            return -1;
        }
        fwrite(out_buffer, 1, out_len, out_file);
    }

    if (EVP_EncryptFinal_ex(ctx, out_buffer, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return -1;
    }
    fwrite(out_buffer, 1, out_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);

    return 0;
}

/**
 * @brief Функция для расшифрования файла.
 * 
 * Расшифровывает содержимое зашифрованного входного файла, используя алгоритм AES-256-CBC. 
 * Сначала из входного файла извлекается соль и вектор инициализации (IV), которые использовались 
 * для шифрования. Затем ключ для расшифрования генерируется на основе пароля, после чего
 * выполняется процесс расшифрования.
 *
 * Алгоритм:
 * 1. Чтение соли и IV из входного файла.
 * 2. Генерация ключа на основе пароля.
 * 3. Расшифрование содержимого и запись в выходной файл.
 *
 * @param in_filename Имя входного файла.
 * @param out_filename Имя выходного файла.
 * @param key Ключ для расшифрования (должен быть длиной 32 байта для AES-256).
 * @param iv Вектор инициализации (должен быть длиной 16 байт для AES-256).
 * @return 0 при успешном расшифровании, -1 в случае ошибки.
 */
int decrypt_file(const char *in_filename, const char *out_filename, const unsigned char *key, const unsigned char *iv) {
    FILE *in_file = fopen(in_filename, "rb");
    FILE *out_file = fopen(out_filename, "wb");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char buffer[1024], salt_buf[SALT_SIZE], iv_buf[IV_SIZE];
    unsigned char out_buffer[1040]; // 1024 + 16 (размер блока)
    int len, out_len;

    if (!in_file || !out_file || !ctx) {
        if (in_file) fclose(in_file);
        if (out_file) fclose(out_file);
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Чтение соли и IV из входного файла
    fread(salt_buf, SALT_SIZE, 1, in_file);
    fread(iv_buf, IV_SIZE, 1, in_file);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return -1;
    }

    while ((len = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buffer, &out_len, buffer, len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_file);
            fclose(out_file);
            return -1;
        }
        fwrite(out_buffer, 1, out_len, out_file);
    }

    if (EVP_DecryptFinal_ex(ctx, out_buffer, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return -1;
    }
    fwrite(out_buffer, 1, out_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);

    return 0;
}

/**
 * @brief Главная функция программы.
 *
 * Инициализирует GTK и создает интерфейс для шифрования/расшифрования файлов.
 *
 * @param argc Количество аргументов командной строки.
 * @param argv Аргументы командной строки.
 * @return 0 при успешном завершении программы.
 */
int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *vbox;
    GtkWidget *entry;
    GtkWidget *encrypt_button;
    GtkWidget *decrypt_button;
    AppWidgets *widgets = g_slice_new(AppWidgets);

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File Encryption");
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 150);

    vbox = gtk_vbox_new(FALSE, 5);

    // Поле для ввода пароля
    entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), TRUE); 
    gtk_entry_set_text(GTK_ENTRY(entry), "Введите пароль");
    widgets->entry = entry;

    // Кнопки
    encrypt_button = gtk_button_new_with_label("Зашифровать");
    decrypt_button = gtk_button_new_with_label("Расшифровать");

    // Подключение сигналов
    g_signal_connect(G_OBJECT(encrypt_button), "clicked", G_CALLBACK(on_encrypt_clicked), widgets);
    g_signal_connect(G_OBJECT(decrypt_button), "clicked", G_CALLBACK(on_decrypt_clicked), widgets);
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Размещение элементов в окне
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), encrypt_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), decrypt_button, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(window), vbox);

    gtk_widget_show_all(window);
    gtk_main();

    g_slice_free(AppWidgets, widgets);

    return 0;
}

