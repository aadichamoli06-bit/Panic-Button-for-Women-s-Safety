/* panic_system_with_auth.c
   Console-based Panic System with:
   1) Simple local user authentication (users.dat)
   2) Offline message queue/resend (offline_queue.dat)

   Notes:
   - Uses libcurl for Telegram sending. Compile with: gcc panic_system_with_auth.c -lcurl -o panic
   - Password hashing uses a simple repeated djb2-style function with salt (portable, no external crypto lib).
     This is NOT cryptographically strong. If you need secure password storage, replace with a proper hash
     (e.g., bcrypt/Argon2 via a library).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>

#define MAX_LEN 200
#define USERS_FILE "users.dat"
#define OFFLINE_QUEUE_FILE "offline_queue.dat"
#define MAX_LINE 1024
#define HASH_ITERS 10007  /* iteration count for simple stretching */

/* ======================================================
   CONFIGURE THESE BEFORE RUNNING
*/
#define BOT_TOKEN "8385445878:AAEDrLNCuWeARbyVUAOdTJr2kg9WrjxTYn8"
/* ====================================================== */

typedef struct Location {
    char name[MAX_LEN];
    double latitude;
    double longitude;
    struct Location *next;
} Location;

typedef struct Contact {
    char name[MAX_LEN];
    long long chat_id; // Telegram chat ID
    int priority;
    struct Contact *next;
} Contact;

typedef struct Panic {
    char timeStr[30];
    char locationLink[MAX_LEN];
    int priority;
    struct Panic *next;
} Panic;

typedef struct User {
    char username[64];
    char salt[32];
    char hash_hex[128];
    struct User *next;
} User;

/* Global heads */
Location *locationHead = NULL;
Contact *contactHead = NULL;
Panic *panicQueue = NULL;
User *userHead = NULL;

/* ======================================================
   Utility
   ====================================================== */
void getCurrentTime(char *buffer, size_t size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void flush_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

/* Read a line into buf (removes trailing newline). Returns 1 on success, 0 on EOF. */
int readline(char *buf, int size) {
    if (!fgets(buf, size, stdin)) return 0;
    buf[strcspn(buf, "\n")] = 0;
    return 1;
}

/* Simple portable pseudo-hash:
   - djb2-like mixing
   - combined with salt and repeated iterations
   **Not** cryptographically secure; acceptable for a small local tool.
*/
void simple_hash_hex(const char *password, const char *salt, char *out_hex, size_t out_len) {
    unsigned long state = 5381;
    size_t pwlen = strlen(password), slen = strlen(salt);
    char *buf = malloc(pwlen + slen + 2);
    if (!buf) { out_hex[0]=0; return; }
    for (int iter = 0; iter < HASH_ITERS; ++iter) {
        /* build iteration string = password + salt + iter */
        int n = snprintf(buf, pwlen + slen + 2, "%s%s%d", password, salt, iter);
        for (int i = 0; i < n; ++i) {
            state = ((state << 5) + state) + (unsigned char)buf[i]; /* state * 33 + c */
            state ^= (state >> ((i & 3) + 1));
            state *= 2654435761u;
        }
    }
    free(buf);
    /* convert state to hex (fixed width) */
    snprintf(out_hex, out_len, "%08lx%08lx", state ^ 0xA5A5A5A5u, (state << 13) | (state >> 19));
}

/* Create a random salt */
void gen_salt(char *salt, size_t size) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t n = strlen(chars);
    srand((unsigned int)time(NULL) ^ (unsigned int)clock());
    for (size_t i=0;i<size-1;i++) salt[i] = chars[rand() % n];
    salt[size-1] = 0;
}

/* ======================================================
   USER MANAGEMENT
   ====================================================== */

void saveUsers() {
    FILE *fp = fopen(USERS_FILE, "w");
    if (!fp) return;
    for (User *u = userHead; u; u = u->next) {
        fprintf(fp, "%s|%s|%s\n", u->username, u->salt, u->hash_hex);
    }
    fclose(fp);
}

void loadUsers() {
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        char usern[64], salt[32], hash[128];
        if (sscanf(line, "%63[^|]|%31[^|]|%127s", usern, salt, hash) == 3) {
            User *n = malloc(sizeof(User));
            if (!n) break;
            strncpy(n->username, usern, sizeof(n->username)-1); n->username[sizeof(n->username)-1]=0;
            strncpy(n->salt, salt, sizeof(n->salt)-1); n->salt[sizeof(n->salt)-1]=0;
            strncpy(n->hash_hex, hash, sizeof(n->hash_hex)-1); n->hash_hex[sizeof(n->hash_hex)-1]=0;
            n->next = userHead; userHead = n;
        }
    }
    fclose(fp);
}

User* findUser(const char *username) {
    for (User *u = userHead; u; u = u->next) if (strcmp(u->username, username) == 0) return u;
    return NULL;
}

int addUser(const char *username, const char *password) {
    if (findUser(username)) return 0;
    User *n = malloc(sizeof(User));
    if (!n) return 0;
    strncpy(n->username, username, sizeof(n->username)-1); n->username[sizeof(n->username)-1]=0;
    gen_salt(n->salt, sizeof(n->salt));
    simple_hash_hex(password, n->salt, n->hash_hex, sizeof(n->hash_hex));
    n->next = userHead; userHead = n;
    saveUsers();
    return 1;
}

/* Interactive new user creation (used for initial admin) */
void createInitialAdminIfNeeded() {
    /* if users.dat missing or no users loaded, create admin */
    if (userHead) return;
    printf("No users found. Create initial admin account.\n");
    char username[64] = {0};
    char password[128] = {0};
    printf("Enter admin username (default 'admin'): ");
    if (!readline(username, sizeof(username))) strncpy(username, "admin", sizeof(username));
    if (strlen(username)==0) strncpy(username, "admin", sizeof(username));
    printf("Enter admin password: ");
    if (!readline(password, sizeof(password)) || strlen(password)==0) {
        printf("Password cannot be empty. Aborting.\n"); exit(1);
    }
    if (addUser(username, password)) printf("Admin '%s' created.\n", username);
    else { printf("Failed to create admin user.\n"); exit(1); }
}

/* Authenticate user; returns 1 if okay, 0 otherwise */
int authenticateUser() {
    char username[64], password[128], hash[128];
    printf("Username: ");
    if (!readline(username, sizeof(username))) return 0;
    printf("Password: ");
    if (!readline(password, sizeof(password))) return 0;
    User *u = findUser(username);
    if (!u) { printf("Unknown user.\n"); return 0; }
    simple_hash_hex(password, u->salt, hash, sizeof(hash));
    if (strcmp(hash, u->hash_hex) == 0) {
        printf("Authentication successful. Welcome, %s.\n", username);
        return 1;
    }
    printf("Authentication failed.\n");
    return 0;
}

/* ======================================================
   TELEGRAM SENDING + OFFLINE QUEUE
   ====================================================== */

/* On send failure, append to offline queue.
   Offline queue file format per line:
     chat_id|timestamp|message_with_escaped_newlines
*/
void appendOfflineMessage(long long chat_id, const char *timeStr, const char *message) {
    FILE *fp = fopen(OFFLINE_QUEUE_FILE, "a");
    if (!fp) return;
    /* escape newlines and '|' characters in message to keep single-line format */
    char esc[MAX_LINE];
    size_t pos = 0;
    for (const char *p=message; *p && pos+4 < sizeof(esc); ++p) {
        if (*p == '\n') { esc[pos++]='\\'; esc[pos++]='n'; }
        else if (*p == '|') { esc[pos++]='\\'; esc[pos++]='|'; }
        else esc[pos++] = *p;
    }
    esc[pos]=0;
    fprintf(fp, "%lld|%s|%s\n", chat_id, timeStr, esc);
    fclose(fp);
}

void url_escape_and_send(CURL *curl, long long chat_id, const char *message);

/* Attempt to resend offline queued messages. Successfully sent messages are removed.
   We read the queue and write back the failures to a temp file; then swap files.
*/
void resendOfflineMessages() {
    FILE *fp = fopen(OFFLINE_QUEUE_FILE, "r");
    if (!fp) { printf("No offline messages queued.\n"); return; }
    FILE *tmp = fopen("offline_queue.tmp", "w");
    if (!tmp) { fclose(fp); printf("Cannot open temp file.\n"); return; }

    char line[MAX_LINE];
    int resent = 0, remaining = 0;
    CURL *curl = curl_easy_init();
    int cancurl = (curl != NULL);
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        /* parse chat_id|timestamp|message */
        char *p1 = strchr(line, '|');
        if (!p1) continue;
        *p1 = 0;
        char *p2 = strchr(p1+1, '|');
        if (!p2) continue;
        *p2 = 0;
        long long chat_id = atoll(line);
        char *ts = p1+1;
        char *msg_esc = p2+1;
        /* unescape message */
        char msg[MAX_LINE]; size_t pos=0;
        for (char *q = msg_esc; *q && pos+1 < sizeof(msg); ++q) {
            if (*q == '\\' && *(q+1) == 'n') { msg[pos++] = '\n'; q++; }
            else if (*q == '\\' && *(q+1) == '|') { msg[pos++] = '|'; q++; }
            else msg[pos++] = *q;
        }
        msg[pos]=0;

        int sent_ok = 0;
        if (cancurl) {
            /* attempt send synchronously using same curl logic */
            CURLcode res;
            char *encoded_message = curl_easy_escape(curl, msg, 0);
            if (encoded_message) {
                char url[1024];
                snprintf(url, sizeof(url),
                         "https://api.telegram.org/bot%s/sendMessage?chat_id=%lld&text=%s",
                         BOT_TOKEN, chat_id, encoded_message);
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                res = curl_easy_perform(curl);
                if (res == CURLE_OK) sent_ok = 1;
                curl_free(encoded_message);
            }
        }
        if (sent_ok) { resent++; printf("Resent queued message to %lld (at %s)\n", chat_id, ts); }
        else {
            /* write back to temp file */
            fprintf(tmp, "%lld|%s|%s\n", chat_id, ts, msg_esc);
            remaining++;
        }
    }
    if (cancurl) curl_easy_cleanup(curl);
    fclose(fp); fclose(tmp);

    /* replace old queue with temp */
    remove(OFFLINE_QUEUE_FILE);
    if (remaining > 0) {
        rename("offline_queue.tmp", OFFLINE_QUEUE_FILE);
    } else {
        remove("offline_queue.tmp");
    }
    printf("Resend complete. Resent: %d Remaining queued: %d\n", resent, remaining);
}

/* Wrapper send function - if fails, append to offline queue */
void send_telegram_message(long long chat_id, const char *message) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        char ts[30]; getCurrentTime(ts, sizeof(ts));
        appendOfflineMessage(chat_id, ts, message);
        fprintf(stderr, "curl init failed: queued message.\n");
        return;
    }

    CURLcode res;
    char *encoded_message = curl_easy_escape(curl, message, 0);
    if (!encoded_message) { curl_easy_cleanup(curl); char ts[30]; getCurrentTime(ts, sizeof(ts)); appendOfflineMessage(chat_id, ts, message); return; }

    char url[1024];
    snprintf(url, sizeof(url),
             "https://api.telegram.org/bot%s/sendMessage?chat_id=%lld&text=%s",
             BOT_TOKEN, chat_id, encoded_message);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        char ts[30]; getCurrentTime(ts, sizeof(ts));
        appendOfflineMessage(chat_id, ts, message);
        fprintf(stderr, "Telegram message failed (queued): %s\n", curl_easy_strerror(res));
    }
    curl_free(encoded_message);
    curl_easy_cleanup(curl);
}

/* ======================================================
   LOCATION FUNCTIONS (unchanged)
   ====================================================== */
void saveLocations() {
    FILE *fp = fopen("locations.dat", "w");
    if (!fp) return;
    for (Location *t = locationHead; t; t = t->next)
        fprintf(fp, "%s|%.8lf|%.8lf\n", t->name, t->latitude, t->longitude);
    fclose(fp);
}

void loadLocations() {
    FILE *fp = fopen("locations.dat", "r");
    if (!fp) return;
    char name[MAX_LEN]; double lat, lon;
    while (fscanf(fp, "%199[^|]|%lf|%lf\n", name, &lat, &lon) == 3) {
        Location *n = malloc(sizeof(Location));
        if (!n) break;
        strncpy(n->name, name, MAX_LEN-1); n->name[MAX_LEN-1]=0;
        n->latitude = lat; n->longitude = lon; n->next = NULL;
        if (!locationHead) locationHead = n;
        else { Location *t = locationHead; while (t->next) t = t->next; t->next = n; }
    }
    fclose(fp);
}

void addLocation(const char *name, double lat, double lon) {
    Location *n = malloc(sizeof(Location));
    if (!n) { printf("Memory error\n"); return; }
    strncpy(n->name, name, MAX_LEN-1); n->name[MAX_LEN-1] = 0;
    n->latitude = lat; n->longitude = lon; n->next = NULL;
    if (!locationHead) locationHead = n;
    else { Location *t = locationHead; while (t->next) t = t->next; t->next = n; }
    saveLocations();
    printf("Location added successfully.\n");
}

void deleteLocation(int num) {
    if (!locationHead) { printf("No locations.\n"); return; }
    Location *prev = NULL, *curr = locationHead;
    int i = 1;
    while (curr && i < num) { prev = curr; curr = curr->next; i++; }
    if (!curr) { printf("Invalid choice.\n"); return; }
    if (!prev) locationHead = curr->next;
    else prev->next = curr->next;
    free(curr); saveLocations();
    printf("Location deleted successfully.\n");
}

void editLocation(int num) {
    if (!locationHead) { printf("No locations available.\n"); return; }
    Location *t = locationHead;
    int i = 1;
    while (t && i < num) { t = t->next; i++; }
    if (!t) { printf("Invalid location number.\n"); return; }

    printf("Editing location '%s'\n", t->name);
    printf("New Name (leave blank to keep): ");
    char buf[MAX_LEN];
    if (!fgets(buf, sizeof(buf), stdin)) buf[0]=0;
    if (buf[0] != '\n') {
        buf[strcspn(buf, "\n")] = 0;
        strncpy(t->name, buf, MAX_LEN-1); t->name[MAX_LEN-1]=0;
    }
    printf("New Latitude (enter 999 if you want to keep current %.8lf): ", t->latitude);
    double newLat, newLon;
    if (scanf("%lf", &newLat)==1) {
        if (newLat != 999) t->latitude = newLat;
    } else { flush_stdin(); }
    printf("New Longitude (enter 999 if you want to keep current %.8lf): ", t->longitude);
    if (scanf("%lf", &newLon)==1) {
        if (newLon != 999) t->longitude = newLon;
    } else { flush_stdin(); }
    getchar();
    saveLocations();
    printf("Location updated successfully.\n");
}

/* ======================================================
   CONTACT FUNCTIONS (unchanged)
   ====================================================== */
void saveContacts() {
    FILE *fp = fopen("contacts.dat", "w");
    if (!fp) return;
    for (Contact *t = contactHead; t; t = t->next)
        fprintf(fp, "%s|%lld|%d\n", t->name, t->chat_id, t->priority);
    fclose(fp);
}

void loadContacts() {
    FILE *fp = fopen("contacts.dat", "r");
    if (!fp) return;
    char name[MAX_LEN]; long long chat_id; int prio;
    while (fscanf(fp, "%199[^|]|%lld|%d\n", name, &chat_id, &prio) == 3) {
        Contact *n = malloc(sizeof(Contact));
        if (!n) break;
        strncpy(n->name, name, MAX_LEN-1); n->name[MAX_LEN-1]=0;
        n->chat_id = chat_id; n->priority = prio; n->next = NULL;
        if (!contactHead || contactHead->priority < prio) { n->next = contactHead; contactHead = n; }
        else {
            Contact *t = contactHead;
            while (t->next && t->next->priority >= prio) t = t->next;
            n->next = t->next; t->next = n;
        }
    }
    fclose(fp);
}

void addContact(const char *name, long long chat_id, int prio) {
    Contact *n = malloc(sizeof(Contact));
    if (!n) { printf("Memory error\n"); return; }
    strncpy(n->name, name, MAX_LEN-1); n->name[MAX_LEN-1]=0;
    n->chat_id = chat_id; n->priority = prio; n->next = NULL;
    if (!contactHead || contactHead->priority < prio) { n->next = contactHead; contactHead = n; }
    else { Contact *t = contactHead; while (t->next && t->next->priority >= prio) t = t->next; n->next = t->next; t->next = n; }
    saveContacts();
    printf("Contact added successfully.\n");
}

void deleteContact(int num) {
    if (!contactHead) { printf("No contacts.\n"); return; }
    Contact *prev = NULL, *curr = contactHead;
    int i = 1;
    while (curr && i < num) { prev = curr; curr = curr->next; i++; }
    if (!curr) { printf("Invalid choice.\n"); return; }
    if (!prev) contactHead = curr->next;
    else prev->next = curr->next;
    free(curr); saveContacts();
    printf("Contact deleted successfully.\n");
}

void editContact(int num) {
    if (!contactHead) { printf("No contacts available.\n"); return; }
    Contact *t = contactHead;
    int i = 1;
    while (t && i < num) { t = t->next; i++; }
    if (!t) { printf("Invalid contact number.\n"); return; }

    printf("Editing contact '%s' (Chat ID: %lld, Priority: %d)\n", t->name, t->chat_id, t->priority);
    printf("New Name (leave blank to keep): ");
    char buf[MAX_LEN];
    if (!fgets(buf, sizeof(buf), stdin)) buf[0]=0;
    if (buf[0] != '\n') {
        buf[strcspn(buf, "\n")] = 0;
        strncpy(t->name, buf, MAX_LEN-1); t->name[MAX_LEN-1]=0;
    }

    printf("New Chat ID (enter 0 to keep %lld): ", t->chat_id);
    long long newId = 0;
    if (scanf("%lld", &newId)==1) {
        if (newId != 0) t->chat_id = newId;
    } else { flush_stdin(); }
    printf("New Priority (1-5, enter 0 to keep %d): ", t->priority);
    int newPrio = 0;
    if (scanf("%d", &newPrio)==1) {
        if (newPrio >=1 && newPrio <=5) t->priority = newPrio;
    } else { flush_stdin(); }
    getchar();

    /* reordering by priority */
    Contact *prev = NULL, *curr = contactHead;
    while (curr && curr != t) { prev = curr; curr = curr->next; }
    if (!curr) { saveContacts(); printf("Saved changes.\n"); return; }
    if (!prev) contactHead = curr->next;
    else prev->next = curr->next;
    if (!contactHead || contactHead->priority < curr->priority) { curr->next = contactHead; contactHead = curr; }
    else {
        Contact *p = contactHead;
        while (p->next && p->next->priority >= curr->priority) p = p->next;
        curr->next = p->next; p->next = curr;
    }

    saveContacts();
    printf("Contact updated successfully.\n");
}

/* ======================================================
   ALERT HISTORY
   ====================================================== */
void appendAlertHistory(const char *timeStr, const char *locName, double lat, double lon, const char *message) {
    FILE *fp = fopen("alerts.dat", "a");
    if (!fp) return;
    fprintf(fp, "%s|%s|%.8lf|%.8lf|%s\n", timeStr, locName, lat, lon, message);
    fclose(fp);
}

void viewAlertHistory() {
    FILE *fp = fopen("alerts.dat", "r");
    if (!fp) { printf("No alert history found.\n"); return; }
    char line[1024];
    int i = 1;
    printf("\n--- ALERT HISTORY ---\n");
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        printf("%d. %s\n", i++, line);
    }
    if (i == 1) printf("No alerts logged yet.\n");
    fclose(fp);
}

/* ======================================================
   PANIC SYSTEM
   ====================================================== */
void appendLog(const char *timeStr, const char *loc) {
    FILE *fp = fopen("logs.dat", "a");
    if (!fp) return;
    fprintf(fp, "%s | %s\n", timeStr, loc);
    fclose(fp);
}

void enqueuePanic(const char *timeStr, const char *googleLink) {
    if (!contactHead) { printf("No contacts to alert.\n"); return; }

    Contact *c = contactHead;
    while (c) {
        Panic *n = malloc(sizeof(Panic));
        if (!n) break;
        strncpy(n->timeStr, timeStr, sizeof(n->timeStr)-1); n->timeStr[sizeof(n->timeStr)-1]=0;
        strncpy(n->locationLink, googleLink, sizeof(n->locationLink)-1); n->locationLink[sizeof(n->locationLink)-1]=0;
        n->priority = c->priority; n->next = NULL;

        if (!panicQueue || panicQueue->priority < n->priority) { n->next = panicQueue; panicQueue = n; }
        else { Panic *t = panicQueue; while (t->next && t->next->priority >= n->priority) t = t->next; n->next = t->next; t->next = n; }

        char message[512];
        snprintf(message, sizeof(message), "🚨 PANIC ALERT 🚨\nTime: %s\nLocation: %s", timeStr, googleLink);
        send_telegram_message(c->chat_id, message);
        printf("Alert processed for: %s [Chat ID %lld, Priority %d]\n", c->name, c->chat_id, c->priority);
        c = c->next;
    }
}

void dequeuePanic() {
    if (!panicQueue) { printf("No pending alerts.\n"); return; }
    Panic *t = panicQueue;
    printf("Processing Alert -> Time: %s | Location: %s | Priority: %d\n", t->timeStr, t->locationLink, t->priority);
    panicQueue = panicQueue->next;
    free(t);
}

/* ======================================================
   PARSE COORDS FROM GOOGLE MAPS LINK (unchanged)
   ====================================================== */
int parseCoordsFromLink(const char *link, double *outLat, double *outLon) {
    if (!link || !outLat || !outLon) return 0;
    const char *p;

    p = strstr(link, "?q=");
    if (!p) p = strstr(link, "&q=");
    if (p) {
        p += 3;
        if (sscanf(p, "%lf,%lf", outLat, outLon) == 2) return 1;
    }

    p = strstr(link, "/@");
    if (p) {
        p += 2;
        if (sscanf(p, "%lf,%lf", outLat, outLon) == 2) return 1;
    }

    p = strstr(link, "ll=");
    if (p) {
        p += 3;
        if (sscanf(p, "%lf,%lf", outLat, outLon) == 2) return 1;
    }

    const char *cursor = link;
    while (*cursor) {
        double a,b;
        if (sscanf(cursor, "%lf,%lf", &a, &b) == 2) {
            *outLat = a; *outLon = b; return 1;
        }
        cursor++;
    }

    return 0;
}

/* ======================================================
   TRIGGER PANIC (updated to log history & use location name + coords)
   ====================================================== */
void triggerPanic() {
    if (!locationHead) { printf("No locations saved.\n"); return; }

    int choice, i = 1;
    for (Location *t = locationHead; t; t = t->next)
        printf("%d. %s (Lat: %.6lf, Lon: %.6lf)\n", i++, t->name, t->latitude, t->longitude);

    printf("Choose location number: ");
    if(scanf("%d", &choice)!=1){ while(getchar()!='\n'); printf("Invalid input.\n"); return; }
    getchar();

    Location *t = locationHead;
    for (i = 1; i < choice && t; i++) t = t->next;
    if (!t) { printf("Invalid choice.\n"); return; }

    char timeStr[30]; getCurrentTime(timeStr, sizeof(timeStr));
    char googleLink[512];
    snprintf(googleLink, sizeof(googleLink), "https://www.google.com/maps?q=%.8lf,%.8lf", t->latitude, t->longitude);

    printf("\nPANIC TRIGGERED!\nTime: %s\nLocation: %s\nLink: %s\n", timeStr, t->name, googleLink);

    /* Send alerts and enqueue */
    enqueuePanic(timeStr, googleLink);
    appendLog(timeStr, googleLink);

    /* Append to alert history with message */
    char msg[512];
    snprintf(msg, sizeof(msg), "Panic at %s (%s)", t->name, googleLink);
    appendAlertHistory(timeStr, t->name, t->latitude, t->longitude, msg);
}

/* ======================================================
   ADD LOCATION MENU
   ====================================================== */
void addLocationInteractive() {
    char name[MAX_LEN];
    double lat=0.0, lon=0.0;
    int choice;

    printf("Location Name: ");
    if (!fgets(name, sizeof(name), stdin)) { printf("Input error.\n"); return; }
    name[strcspn(name, "\n")] = 0;
    if (strlen(name) == 0) { printf("Name cannot be empty.\n"); return; }

    printf("Choose input type:\n1. Enter coordinates manually\n2. Paste Google Maps link\nChoice: ");
    if (scanf("%d", &choice)!=1) { flush_stdin(); printf("Invalid input.\n"); return; }
    getchar();

    if (choice == 1) {
        printf("Latitude: "); if (scanf("%lf", &lat)!=1) { flush_stdin(); printf("Invalid latitude.\n"); return; }
        printf("Longitude: "); if (scanf("%lf", &lon)!=1) { flush_stdin(); printf("Invalid longitude.\n"); return; }
        getchar();
        addLocation(name, lat, lon);
    } else if (choice == 2) {
        char link[512];
        printf("Paste Google Maps link: ");
        if (!fgets(link, sizeof(link), stdin)) { printf("Input error.\n"); return; }
        link[strcspn(link, "\n")] = 0;
        if (parseCoordsFromLink(link, &lat, &lon)) {
            printf("Extracted coordinates: %.8lf, %.8lf\n", lat, lon);
            addLocation(name, lat, lon);
        } else {
            printf("Could not parse coordinates from link. Try entering manually.\n");
        }
    } else {
        printf("Invalid choice.\n");
    }
}

/* ======================================================
   CLEANUP
   ====================================================== */
void freeAll() {
    while(contactHead){ Contact *t=contactHead; contactHead=contactHead->next; free(t); }
    while(locationHead){ Location *t=locationHead; locationHead=locationHead->next; free(t); }
    while(panicQueue){ Panic *t=panicQueue; panicQueue=panicQueue->next; free(t); }
    while(userHead){ User *t=userHead; userHead=userHead->next; free(t); } /* note: this free loop is safe */
}

/* ======================================================
   MAIN
   ====================================================== */
int main() {
    int ch, num, prio;
    char name[MAX_LEN]; double lat, lon;
    long long chat_id;

    loadContacts(); loadLocations();
    loadUsers();
    createInitialAdminIfNeeded();

    /* Authenticate user before allowing actions */
    printf("\n--- Please login ---\n");
    int tries = 0, ok = 0;
    while (tries < 3 && !ok) { if (authenticateUser()) ok = 1; else tries++; }
    if (!ok) { printf("Authentication failed. Exiting.\n"); return 1; }

    /* Try to resend any queued offline messages at startup */
    curl_global_init(CURL_GLOBAL_ALL);
    printf("Attempting to resend any offline queued messages...\n");
    resendOfflineMessages();

    do {
        int i;
        printf("\n--- PANIC SYSTEM ---\n");
        printf("1. Trigger Panic\n2. Add Location\n3. Edit Location\n4. Delete Location\n5. View Locations\n");
        printf("6. Add Contact\n7. Edit Contact\n8. Delete Contact\n9. View Contacts\n");
        printf("10. View Alert History\n11. Process Alerts (dequeue)\n12. Resend Offline Messages\n13. Exit\nChoice: ");
        if(scanf("%d",&ch)!=1){ while(getchar()!='\n'); ch=0; }
        getchar();

        switch(ch){
            case 1: triggerPanic(); break;

            case 2:
                addLocationInteractive();
                break;

            case 3:
                i=1; for(Location *t=locationHead;t;t=t->next) printf("%d. %s (%.6lf, %.6lf)\n", i++, t->name, t->latitude, t->longitude);
                if (i==1) { printf("No locations.\n"); break; }
                printf("Enter number to edit: "); if(scanf("%d", &num)!=1){ while(getchar()!='\n'); printf("Invalid input.\n"); break; } getchar();
                editLocation(num); break;

            case 4:
                i=1; for(Location *t=locationHead;t;t=t->next) printf("%d. %s (%.6lf, %.6lf)\n", i++, t->name, t->latitude, t->longitude);
                if (i==1) { printf("No locations.\n"); break; }
                printf("Enter number to delete: "); if(scanf("%d",&num)!=1){ while(getchar()!='\n'); printf("Invalid input.\n"); break; } getchar();
                deleteLocation(num); break;

            case 5:
                i=1; for(Location *t=locationHead;t;t=t->next) printf("%d. %s (Lat: %.6lf, Lon: %.6lf)\n", i++, t->name, t->latitude, t->longitude);
                if(i==1) printf("No locations saved.\n");
                break;

            case 6:
                printf("Name: "); if (!fgets(name, sizeof(name), stdin)) { printf("Input error.\n"); break; } name[strcspn(name,"\n")] = 0;
                printf("Chat ID: "); if (scanf("%lld", &chat_id)!=1) { flush_stdin(); printf("Invalid chat id.\n"); break; }
                printf("Priority (1-5): "); if (scanf("%d",&prio)!=1){ flush_stdin(); printf("Invalid priority.\n"); break; } getchar();
                addContact(name, chat_id, prio); break;

            case 7:
                i=1; for(Contact *t=contactHead;t;t=t->next) printf("%d. %s - %lld [Priority %d]\n", i++, t->name, t->chat_id, t->priority);
                if (i==1) { printf("No contacts.\n"); break; }
                printf("Enter number to edit: "); if(scanf("%d", &num)!=1){ while(getchar()!='\n'); printf("Invalid input.\n"); break; } getchar();
                editContact(num); break;

            case 8:
                i=1; for(Contact *t=contactHead;t;t=t->next) printf("%d. %s - %lld [Priority %d]\n", i++, t->name, t->chat_id, t->priority);
                if (i==1) { printf("No contacts.\n"); break; }
                printf("Enter number to delete: "); if(scanf("%d",&num)!=1){ while(getchar()!='\n'); printf("Invalid input.\n"); break; } getchar();
                deleteContact(num); break;

            case 9:
                i=1; for(Contact *t=contactHead;t;t=t->next) printf("%d. %s - %lld [Priority %d]\n", i++, t->name, t->chat_id, t->priority);
                if(i==1) printf("No contacts saved.\n");
                break;

            case 10:
                viewAlertHistory();
                break;

            case 11:
                dequeuePanic();
                break;

            case 12:
                resendOfflineMessages();
                break;

            case 13:
                printf("Exiting...\n");
                break;

            default: printf("Invalid choice.\n");
        }
    } while(ch!=13);

    freeAll();
    curl_global_cleanup();
    return 0;
}
