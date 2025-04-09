#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "crypto.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */
unsigned char session_key[SHA256_DIGEST_LENGTH];

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */

	// Encrypt the message
    unsigned char iv[AES_IVLEN];  // IV for encryption
    unsigned char ciphertext[1024];  // Buffer for the encrypted message
    int ciphertext_len = encrypt_message((unsigned char*)message, len, session_key, iv, ciphertext);

	// Display the encrypted message in hex
    printf("Encrypted Message (Hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Combine IV and ciphertext into one buffer for sending
    unsigned char outbuf[AES_IVLEN + ciphertext_len];
    memcpy(outbuf, iv, AES_IVLEN);
    memcpy(outbuf + AES_IVLEN, ciphertext, ciphertext_len);

	ssize_t nbytes;
	if ((nbytes = send(sockfd, outbuf, AES_IVLEN + ciphertext_len, 0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	// === Diffie-Hellman Exchange protocol ===

	init("params"); // or initFromScratch(...) but the params are located in the params file for key generation

	// Allocate public key buffers based on pLen
	uint8_t* public_key_buf = malloc(pLen);
	uint8_t* their_public_key_buf = malloc(pLen);
	uint8_t local_session_key[SHA256_DIGEST_LENGTH];

	// Initialize big numbers
	mpz_t sk, pk, their_pk;
	mpz_inits(sk, pk, their_pk, NULL);
	/*
	gmp_printf("Private Key: %Zd\n", sk); // Keys before they are generated should be 0. (debugging)
	gmp_printf("Public Key: %Zd\n", pk); 
	*/

	// Generate the DH keys
	dhGen(sk, pk);
	
	gmp_printf("Private Key: %Zd\n", sk); // After generation (debugging)
	gmp_printf("Public Key: %Zd\n", pk);
	

	// Export our public key to the byte buffer (I had to look up the functions to do this.)
	size_t count;
	mpz_export(public_key_buf, &count, 1, 1, 0, 0, pk);

	// Send public key
	if (send(sockfd, public_key_buf, pLen, 0) == -1) {
		perror("Failed to send public key");
		exit(EXIT_FAILURE);
	}

	// Receive peer's public key
	if (recv(sockfd, their_public_key_buf, pLen, MSG_WAITALL) == -1) {
		perror("Failed to receive public key");
		exit(EXIT_FAILURE);
	}

	// Import received public key into mpz_t
	mpz_import(their_pk, pLen, 1, 1, 0, 0, their_public_key_buf);

	// Get the shared session key
	dhFinal(sk, pk, their_pk, local_session_key, sizeof(local_session_key));

	// Copy to global session key to access for later
	memcpy(session_key, local_session_key, SHA256_DIGEST_LENGTH);

	// Print session keys to make sure they match for both processes
	fprintf(stderr, "Session key: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		fprintf(stderr, "%02x", local_session_key[i]);
	}
	fprintf(stderr, "\n");

	// Cleanup and freeing the memory of pointers and values
	free(public_key_buf);
	free(their_public_key_buf);
	mpz_clears(sk, pk, their_pk, NULL);

	// By this point, we set up the MAC using the session key generated to authenticate messages

	unsigned char challenge_message[] = "Challenge: Authenticate me!";
	unsigned char challenge_response[SHA256_DIGEST_LENGTH];

	// Generate HMAC of the challenge using the session key (Also had to look this up)
	HMAC_CTX *hmac_ctx = HMAC_CTX_new();
	HMAC_Init_ex(hmac_ctx, local_session_key, sizeof(local_session_key), EVP_sha256(), NULL);
	HMAC_Update(hmac_ctx, challenge_message, strlen(challenge_message));
	HMAC_Final(hmac_ctx, challenge_response, NULL);
	HMAC_CTX_free(hmac_ctx);

	// Send the challenge response (HMAC) to the remote party
	send(sockfd, challenge_response, sizeof(challenge_response), 0);

	unsigned char received_challenge_response[SHA256_DIGEST_LENGTH];

	// Receive challenge response from the remote party
	if (recv(sockfd, received_challenge_response, sizeof(received_challenge_response), MSG_WAITALL) == -1) {
    	perror("Failed to receive challenge response");
    	exit(EXIT_FAILURE);
	}

	// Verify the challenge response using HMAC and session key
	unsigned char expected_response[SHA256_DIGEST_LENGTH];
	HMAC_CTX *hmac_ctx_verify = HMAC_CTX_new();
	HMAC_Init_ex(hmac_ctx_verify, local_session_key, sizeof(local_session_key), EVP_sha256(), NULL);
	HMAC_Update(hmac_ctx_verify, challenge_message, strlen(challenge_message));
	HMAC_Final(hmac_ctx_verify, expected_response, NULL);
	HMAC_CTX_free(hmac_ctx_verify);

	// Compare the received response with the expected response
	if (memcmp(received_challenge_response, expected_response, sizeof(expected_response)) == 0) {
    	printf("Mutual authentication successful!\n");
	} else {
    	printf("Authentication failed.\n");
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}

		printf("Received Encrypted Message (Hex): ");
        for (int i = 0; i < nbytes; i++) {
            printf("%02x", (unsigned char)msg[i]);
        }
        printf("\n");

		// Extract the IV from the first AES_IVLEN bytes of the received message
        unsigned char iv[AES_IVLEN];
        memcpy(iv, msg, AES_IVLEN);

        // Decrypt the ciphertext part of the message
        unsigned char decrypted_msg[1024];
        int decrypted_len = decrypt_message(msg + AES_IVLEN, nbytes - AES_IVLEN, session_key, iv, decrypted_msg);

        // Null-terminate the decrypted message
        decrypted_msg[decrypted_len] = '\0';

        // Show the decrypted message in the GTK interface
        char* m = strdup((char*)decrypted_msg);
        g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}