#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 51969
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: "
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define QUIT_MSG "quit"
#define UNIQUENESS_ERR "Please enter a unique non-empty username: "
#define INVALID_ERR "Invalid command\r\n"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user

    int num_messages;//number of tweets made
    int num_following;//number of Clients this user is following
    int num_followers;//number of Clients who follow this user

    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);


// New helpers
int follow(struct client *follower, char* user_followed, struct client *active_clients);
int unfollow(struct client *follower, char* user_followed);
int send_tweet(struct client *c, char* m);
int show_tweets(struct client *c);
int client_quit(struct client *c, struct client* active_clients);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client *active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr){
    //add c in to active clients
    add_client(active_clients_ptr, c->fd, c->ipaddr);
    strcpy((*active_clients_ptr)->username, c->username);
    //find where c is in the new clients list and remove it by shifting elements left
    struct client* n_c = *new_clients_ptr;
    if(c->fd == n_c->fd){
        *new_clients_ptr = (*new_clients_ptr)->next;
    }
    while(n_c->next != NULL){
        if(c->fd == n_c->next->fd){
            n_c->next = n_c->next->next;
            break;
        }
        n_c = n_c->next;
    }
}


// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    //initializing new variables
    p->num_followers = 0;
    p->num_following = 0;
    p->num_messages = 0;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // TODO: Remove the client from other clients' following/followers
        // lists

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free((*p)->following);
        free((*p)->followers);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }

}


//New helpers:
char* command_check(struct client *c, char* message, struct client *active_clients){
    char storage[BUF_SIZE];
    strcpy(storage, message);
    char* command = strtok(storage, " ");
    int command_result;
    char* command_message = NULL;
    if(strcmp(command, FOLLOW_MSG) == 0){
        char* username = strtok(NULL, " ");
        printf("%s\n",c->username);
        printf("%s is trying to follow %s\n", c->username, username);
        command_result = follow(c, username, active_clients);
        if(command_result == 0){
            printf("Follow was successful.\n");
        }
        else if(command_result == -1){
            printf("Client followed an invalid user.\n");
            command_message = "User invalid, please follow a valid user.\r\n";
        }
        else if(command_result == -2){
            printf("Client or user followed has reached the follow limit.\n");
            command_message = "Either you have reahced the follow limit, or the user you are attempting to follow has.\r\n";
        }
    }
    else if(strcmp(command, UNFOLLOW_MSG) == 0){
        char* username = strtok(NULL, " ");
        printf("%s is trying to unfollow %s\n", c->username, username);
        command_result = follow(c, username, active_clients);         
        if(command_result == 0){
            printf("Unfollow was successful.\n");
        }
        else if(command_result == -1){
            printf("Client Unfollowed invalid user.\n");
            command_message = "User invalid, please unfollow a valid user.\r\n";
        }        
    }
    else if(strcmp(command, SHOW_MSG) == 0){
        command_result = show_tweets(c);
        printf("%s is trying to view tweets. \n", c->username);
        printf("Tweets shown successfully.\n");
    }
    else if(strcmp(command, "send") == 0){
        printf("%s is trying to tweet a message. \n", c->username);

        command_result = send_tweet(c, message); 
        if(command_result == 0){
            printf("Tweet sent successfully.\n");
        }
        else if(command_result == -1){
            printf("Client has reached the message limit.\n");
            command_message = "You have reached the tweet limit.\r\n";
        }
        else if(command_result == -2){
            printf("Client message is longer than the allowed limit.\n");
            command_message = "Your tweet is longer than the allowed limit.\r\n";
        }        
    }
    else if(strcmp(command, QUIT_MSG) == 0){
        printf("%s is trying to tweet a message. \n", c->username);
        command_result = client_quit(c, active_clients);
        if(command_result == 0){
            printf("Client successfully disconnected.\n");
        }
        else{
            printf("Client successfully did not successfully disconnect.\n");
        }
    }
    else{
        command_message = INVALID_ERR;
    }
    return command_message;
}


//Have the follower follow a user 
//Return -1 if the client follows an invalid user, 
//Return -2 if the client has reached the follow limit or the followed user has reached the follower limit,
//Return 0 if the follow command is successful. 
int follow(struct client *follower, char* user_followed, struct client *active_clients){
    //Check if the user is following themself
    if(strcmp(user_followed, follower->username) == 0){
        return -1;
    }

    //find if the user_followed exists
    for(struct client *q = active_clients; q != NULL; q = q->next){
        if(strcmp(user_followed, q->username) == 0){
            //check follower and following limits for both users.
            if(follower->num_following == 5 || q->num_followers == 5){
                return -2;
            }
            follower->following[follower->num_following] = q;
            q->followers[q->num_followers] = follower;
            follower->num_following ++;
            q->num_followers ++;
            return 0;
        }
    }
    return -1;
}
//Have the follower unfollow a user
//Return -1 if the client unfollows an invalid user, 
//Return 0 if the follow command is successful. 
int unfollow(struct client *follower, char* user_followed){
    //Check if the user is unfollowing themself
    if(strcmp(user_followed, follower->username) == 0){
        return -1;
    }

    //find if the user_followed is being followed by the client 
    int i_following;
    for(i_following = 0; i_following < follower->num_following; i_following++){
        if(strcmp(user_followed, follower->following[i_following]->username) == 0){
            //First remove the client from user_followed's follower array
            struct client* target = follower->following[i_following];
            int i_follower;
            for(i_follower = 0; i_follower < target->num_followers; i_follower++){
                if(strcmp(follower->username, target->followers[i_follower]->username) == 0){
                    break;
                }
            }
            for(int shift = i_follower; shift < FOLLOW_LIMIT - 1; shift++){
                target->followers[shift] = target->followers[shift + 1];
            }
            target->num_followers -= 1;
            //Second remove the user_followed from the client's following array
            for(int shift = i_following; shift < FOLLOW_LIMIT - 1; shift++){
                follower->following[shift] = follower->following[shift + 1];
            }
            follower->num_followers -= 1;
            return 0;
        }
    }
    return -1;
}

//Have the client send a tweet
//Return -2 if the client's tweet is longer than the allowed character limit, 
//Return -1 if the client has reached the MSG_LIMIT, 
//Return 0 if the send_tweet command is successful. 
int send_tweet(struct client *c, char* m){
    //Check if the client has reached the MSG_LIMIT
    if(c->num_messages == MSG_LIMIT){
        return -1;
    }
    //extract the message from the line
    printf("%s\n", m);
    char message[strlen(m) - 4];
    memcpy(message, &m[5], strlen(m) - 4);
    message[strlen(m)-5] = '\0';

    //Check if the tweet has an acceptable length
    if(strlen(message) > 140){
        return -2;
    }
    //Convert message to the correct format.
    char formated_msg[BUF_SIZE];
    strncpy(formated_msg, c->username, strlen(c->username)+1);
    strcat(formated_msg,": ");
    strcat(formated_msg, message);
    strcat(formated_msg, "\0\r\n");
    formated_msg[BUF_SIZE-1] = '\0';
    //send to every user that follows the client.
    for(int follower = 0; follower < c->num_followers; follower++){
        int followerfd = c->followers[follower]->fd;
        if (write(followerfd, formated_msg, strlen(formated_msg)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", c->username);
        }
    }
    //Add message to the client's message archive
    strcpy(c->message[c->num_messages], message);
    c->num_messages++;
    return 0;
}

//Show the tweets that have been sent by this client's followed users
int show_tweets(struct client *c){
    char formated_msg[BUF_SIZE];
    char message[BUF_SIZE];
    struct client* f;
    //go through each user that the client is following
    for(int curr_f = 0; curr_f < c->num_following; curr_f++){
        f = c->following[curr_f];
        //go through all of the current user's messages
        for(int curr_m = 0; curr_m < f->num_messages; curr_m++){
            strcpy(message, f->message[curr_m]);
            strcpy(formated_msg, f->username);
            strcat(formated_msg," wrote: ");
            strcat(formated_msg, message);
            strcat(formated_msg, "\0\r\n");
            formated_msg[BUF_SIZE-1] = '\0';
            if (write(c->fd, formated_msg, strlen(formated_msg)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", c->username);
            }
        }
    }
    return 0;
}
//Disconnect the client from the server
int client_quit(struct client *c, struct client* active_clients){
    //remove this client from the all following and follower list of other users.
    int quit_result = 0;
    for(int i = c->num_following - 1; i >= 0; i--){
        quit_result = unfollow(c, c->following[i]->username); 
    }
    for(int i = c->num_followers - 1; i >= 0; i--){
        quit_result = unfollow(c->followers[i], c->username); 
    }
    //remove this client from active clients
    remove_client(&active_clients, c->fd);
    return quit_result;
}


int newline_location(const char *buf, int num){
    for(int index = 0; index < num-1; index++){
        if(buf[index] == '\r' && buf[index + 1] == '\n'){
            return index+2;
        }
    }
    return -1;
}

int client_read(struct client *c, struct client* active_clients, struct client* new_clients, int type){
    char message[BUF_SIZE];
    int space = BUF_SIZE;
    char* msg_ptr = message;
    int message_len = 0;
    int location;
    int num_bytes;
    while((num_bytes = read(c->fd, msg_ptr, space)) > 0){
        message_len = num_bytes + message_len;
        location = 0;
        while((location = newline_location(message, message_len)) > 0){
            message[location - 2] = '\0';
            printf("%s\n",message);
            printf("%d\n",num_bytes);
            if(num_bytes == 2){
                strcpy(c->inbuf, "");
                printf("detected nothing\n");
                return -1;
            }
            if(type == 0){
                struct client *p2;
                for(p2 = active_clients; p2 != NULL; p2 = p2->next){
                    if(strlen(message) == 0||strcmp(message, p2->username) == 0){
                        char *uniqueness = UNIQUENESS_ERR;
                        if (write(c->fd, uniqueness, strlen(uniqueness)) == -1) {
                            fprintf(stderr, "Write to client failed\n");
                            remove_client(&new_clients, c->fd);
                        }
                        printf("invalid username detected\n");
                        return -1;
                    }                            
                }
                printf("Valid username detected\n");
                strcpy(c->username, message);
                return 0;
            }
            else if(type == 1){
                printf("Command detected\n");
                strcpy(c->inbuf, message);
            }
            return 0;

            // memmove(message, message + location, BUF_SIZE - location);
            // message_len = message_len - location;
        }
        msg_ptr = message + message_len;
        space = BUF_SIZE - message_len;
    }
    return 1;
}

int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled, read_result;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // TODO: handle input from a new client who has not yet
                        // entered an acceptable name

                        //loop read to get the e
                        read_result = client_read(p, active_clients, new_clients, 0);
                        if(read_result == 0){
                            printf("Activating %s's account\n",p->username);
                            activate_client(p, &active_clients, &new_clients);
                        }
                        else if(read_result == 1){
                            client_quit(p, active_clients);
                            printf("The user %s has left", p->username);
                        }
                    }
                    handled = 1;
                    break;

                }
                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // TODO: handle input from an active client
                            //Check which command was issued.
                            read_result = client_read(p, active_clients, new_clients, 1);
                            printf("%s\n",p->username);

                            if(read_result == 1){
                                client_quit(p, active_clients);
                                printf("The user %s has left", p->username);
                            }
                            else if(read_result == -1){
                                if (write(cur_fd, INVALID_ERR, strlen(INVALID_ERR)) == -1) {
                                    fprintf(stderr, "Write to client %s failed\n", p->username);
                                }
                            }
                            else{
                                char* command_message = command_check(p, p->inbuf, active_clients);
                                if(command_message != NULL){
                                    if (write(cur_fd, command_message, strlen(command_message)) == -1) {
                                        fprintf(stderr, "Write to client %s failed\n", p->username);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
