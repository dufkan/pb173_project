#ifndef SERVER_HPP
#define SERVER_HPP

#include <vector>
#include <string>

#include "asio.hpp"
#include "../shared/message.hpp"
#include "../shared/crypto.hpp"


/**
 * Starts server ~ listening on TCP ip:port.
 *
 * @param ip IP address of the server
 * @param port TCP port of the server
 */
void server(/* ip */, /* port */);

/**
 * Accepts a connection from acceptor
 *
 * @param acceptor Acceptor object listening to connections.
 */
void accept_connection(/* asio::tcp::acceptor& acceptor */);

/**
 * Receives a message from connection.
 *
 * @param conn Connection to recieve message from
 */
std::vector<uint8_t> recv_message(/* asio::tcp::connection& conn */);

/**
 * Sends a message to connection.
 *
 * @param conn Connection to send to
 */
void send_message(/* asio::tcp::connection& conn */, msg::Message& message);

/**
 * Add new user to database.
 *
 * @param pseudonym Pseudonym of the user
 * @param pubkey Public key of the user
 */
void add_user(std::string pseudonym, std::vector<uint8_t> pubkey);

/**
 * Get user information from database.
 *
 * @param pseudonym Pseudonym of the user
 */
std::vector<uint8_t> get_user(std::string pseudonym);

/**
 * Create challenge message for challenge-response protocol.
 *
 * @param pubkey Public key to use for challenge encryption
 */
msg::Challenge create_challenge(std::vector<uint8_t> pubkey);

/**
 * Create response message for challenge-response protocol.
 *
 * @param challenge Received challenge
 * @param pubkey Public key of the response recipient
 */
msg::Response create_response(std::vector<uint8_t> challenge, std::vector<uint8_t> pubkey);


#endif
