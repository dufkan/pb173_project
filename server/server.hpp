#ifndef SERVER_HPP
#define SERVER_HPP

#include <vector>
#include <string>
#include <iostream>
#include <iterator>
#include <fstream>
#include <map>
#include <cstdio>
#include <utility>

//#include "asio.hpp"
#include "../shared/messages.hpp"
#include "../shared/crypto.hpp"
#include "../shared/channel.hpp"

class Server {
public:
    std::map<std::string, Channel> connections;

    std::vector<std::string> get_connected_users() {
        std::vector<std::string> connected;
        connected.reserve(connections.size());
        for(auto& c : connections) {
            connected.push_back(c.first);
        }
        return connected;
    }

    /**
     * Handling of an incomming connection ~ Authentication,
     * key agreement, creation of channel.
     */
    void handle_new_connection() {
    }
};

/**
 * Starts server ~ listening on TCP ip:port.
 *
 * @param ip IP address of the server
 * @param port TCP port of the server
 */
//void server(/* ip */, /* port */);

/**
 * Accepts a connection from acceptor
 *
 * @param acceptor Acceptor object listening to connections.
 */
//void accept_connection(/* asio::tcp::acceptor& acceptor */);

/**
 * Receives a message from connection.
 *
 * @param conn Connection to recieve message from
 *
 * @return Vector of bytes of received message
 */
//std::vector<uint8_t> recv_message(/* asio::tcp::connection& conn */);

/**
 * Sends a message to connection.
 *
 * @param conn Connection to send to
 */
//void send_message(/* asio::tcp::connection& conn */, msg::Message& message);

/**
 * Read contents of file.
 *
 * @param fname Name of file to read from
 * @return File contents
 */
std::vector<uint8_t> read_file(const std::string& fname);

/**
 * Write vector of bytes into file.
 *
 * @param fname Name of file to write to
 * @param data Bytes to write
 */
void write_file(const std::string& fname, const std::vector<uint8_t>& data, bool append = false);

/**
 * Add new user to database.
 *
 * @param pseudonym Pseudonym of the user
 * @param pubkey Public key of the user
 * @return False if user already exists; true otherwise
 */
bool add_user(std::string pseudonym, std::vector<uint8_t> pubkey);

/**
 * Remove user from the database.
 *
 * @param pseudonym Pseudonym of the user
 * @return True if operation succeded; false otherwise
 */
bool remove_user(std::string pseudonym);

/**
 * Get user information from database.
 *
 * @param pseudonym Pseudonym of the user
 *
 * @return Information about the user (public key)
 */
std::vector<uint8_t> get_user(std::string pseudonym);

#endif
