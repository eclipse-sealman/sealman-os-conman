/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "config/command_line.h"
#include "config/common_options.h"

namespace config
{

namespace //anonymous
{

namespace po = boost::program_options;
using namespace std::literals;

struct CommandLine : CommonOptions
{
#if 1 // for folding :)
	static constexpr std::string_view long_help = R"RAW_LITERAL(
This protocol allows Push/Sub bus messaging and reliable Query/Response
messaging between *clients* with help of *Forwarder*. Protocol assumes clients
are benevolent, but may be buggy. Protocol uses multipart ZMQ messages.

In description below Client/Sender/Receiver refers to the one interacting
currently with Forwarder (i.e. on behaviour of which you as protocol user have
direct control), while client/sender/receiver refers to any other client which
is/was connected to Forwarder.

Message synpis
====

Following grammar is used when describing messages:

 * whole (multipart) message synopis is enclosed in "<>" symbols
 * parts of multipart messages are split by "|" symbol
 * optional parts are enclosed in "[]" symbols
 * raw values of whole parts in messages are given in double quotes
 * raw values of single bytes in parts are given in single quotes


There are some common data types used inside parts:

TopicType     --- arbitrary length of bytes (preferably human readable string)
ClientIdType  --- 8 bytes long identifiers of client
SequenceType  --- 3 byte identifier of message from client on given topic
GlobalSequenceType --- 8 bytes long integer


Cli socket
====

Cli socket is of type ZMQ_REP and Client shall connect to it using ZMQ_REQ
socket. For any request sent to this socket there will be response. For valid
requests responses are described below each request type. If request is invalid
the response will be:
 * <"RESET"> --- if request was HANDLE, PING, GOODBYE or any other request which
   second part shall be PrivateId of Sender. This response means that Forwarder
   does not know anything about Client's PrivateId received in request (can happen
   e.g. in case Forwarder was restarted while Client was alive, or if Client was
   not sending PING messages for long time), or that according to Forwarder the
   Client is not responding to queries as advertised by him earlier with help of
   HANDLE messages, or that Forwarder wants to change private or public id used
   by Client. After receiving RESET Client shall again send HELLO and HANDLE
   messages. Forwarder currently uses IPC transport be default, but in some
   transport protocols it may be also needed to reconnect to sub socket and
   perform subscriptions again before sending HANDLE messages. Note that
   nothing prevents Client (if it is aware of yet unaswered queries)
   to send the responses despite receiving RESET message.
 * <"INVALID"|Reason> --- for any message if there were problems with its
   contents. Reason is ASCII message describing what was wrong with message
   according to Forwarder.

<"HELLO"[|OldPublicId[|OldPrivateId]]> --- new Client shall send message to
this socket. Client shall fill both OldPublicId and OldPrivateId if it performs
HELLO due to RESET. Client may optionally fill OldPublicId without OldPrivateId
if it is new connection, but it would like to use specifc PublicId. In response
Client will receive:
 * <"ID"|PrivateId|PublicId> Only after receiving PrivateId Client
   can send meaningfull messages to Push socket and register handlers for
   topics. PublicId is needed to verify that Client received answer to its own
   requests (or to verify that its own messages were actually published).
   Note that PrivateId->PublicId pair is not intended as security mechanism, but
   rather as way to protect from server and Client crashes and non-intentional
   protocol misbehaviours.

<"HANDLE"|PrivateId|Query|Response[|Query|Response ...]> --- Client sends this
message to indicate that it is going to respond to messages with specific topic
seen in Push socket. Client shall send HANDLE message to Req socket after
subscribing to topic(s) via Sub socket. In HANDLE message each Query part
contains topic Client is going to respond to, and each Response part following
immediately a Query part is topic with which response will be sent. Response to
HANDLE message will be either:
 * <X[X...]> where for each Query/Response pair in HANDLE message there will be
   a byte X with following possible values 'U', 'A', 'D' meaning that respective
   Query/Response pair is currently Unique (i.e. no other handler responsds to
   same Query), Accessory (there is other handler for same Query but it uses
   different response topic) or Duplicate (there is another handler using same
   response topic). Note however that those value are just informational ---
   i.e. duplicates are allowed, although they may indicate some issues in
   configuration of Clients).

<"PING"|PrivateId> --- long living Client shall send PING message with its own
PrivateId at least once per mgmtd configured period (default 1 second).
Response to such ping packets will be either:
 * <"OK"> --- all looks good
 * <"LOST"|QueryTopic|MessageId|ResponseTopic[|QueryTopic|MessageId|ResponseTopic...]>
   where each QueryTopic part will be topic of message previously sent by this Client
   to Push socket with Resp first byte 'Q' for which Forwarder thinks that
   response will not come back because registered handlers of this topic are not
   present (or were not present at the time of sending the query to Push
   socket). ResponseTopic will be "?" if not known.

<"GOODBYE"|PrivateId> --- if possible, just before disconnection Client shall
send GOODBYE message to indicate its disconnection (although Forwarder will
treat Client as gone after some time without pings even if GOODBYE is not
sent). Possible responses to GOODBYE are identical as to PING, of course in
case of RESET response no action is needed, as Client was going to disconnect
anyway.

<"STAT"|Id> --- Client may (for debug purposes) send STAT message with any
PrivateId or PublicId. The response will be:
 * <Published|Queries|Unaswered|Lost|Responses>, where each part is ASCII
   string representation of number of specific type of messages from the Id
   received in Push socket.

<"EXISTS"|Topic[|Topic ...]> --- Client may send this message to receive
information if there is at least one sink/handler for given Topic (or Topics).
Topic will be treated as regex which shall match against whole existing topic
name. Response will be
 * <X[X...]> --- where in for each topic sent in request there will be a byte X
   with following possible values: 'S' 'H' 'N' meaning respectively Sink,
   Handler, None

<"LIST_SERVICES"[|Topic ...]> --- Client may send this message to receive list
of topics to which there are currently registered handlers. If there are any
Topics in query, then they are treated as regex(es) which shall match whole
existing topic(s) name.
 * <Count|Topic|[Topic ...]> --- where count is ASCII representation of number of
   topics following

<"LIST_SINKS"[|Topic ...]> --- silimar to LIST_SERVICES but in regard to
listeners who do not advertise sending repsonses. Note that topic cannot be
both in LIST_SERVICES and LIST_SINKS response, because sinks are not required
to register themeselves specifically as sinks.

<"LIST_TOPICS"[|Topic ...]> --- similar to LIST_SERVICES and LIST_SINKS ---
response is mathematical set sum of responses for those two queries.


Push socket
====

Push socket is of type ZMQ_PULL and Client shall connect to it using ZMQ_PUSH.
Client (if possible) shall avoid sending messages to topics for which there are
no listeners currently, however this is not enforced (ZMQ_PUSH/PULL is used
intentionally instead of PUB/SUB to allow detection of such cases --- ZMQ_PUB/SUB
would perform such filtering automatically but also silently --- Client would
never know that messages was dropped).

Push socket accepts multipart messages in format
<Topic|PrivateId|PublicId|MessageId|Body[|...]> where
 * Topic is message topic
 * PrivateId and PublicId shall belong to the sender
 * MessageId first byte shall be 'Q' if this is a query requiring response, or
   'M' if this is standalone annoucement to Push bus, or 'R' if this message is
   response to a previous query. After 'M' or 'Q' there shall be value of
   SequenceType --- exactly 3 bytes with message identifier (AKA sequence
   number). For queries this identifier shall be created by Client as unique one
   for yet unanswerd queries. After 'R' there shall be copy of PublicId and
   MessageId fields found in query concatenated together.
 * Body is potentially multipart and depends on Topic


Sub socket
====

Sub socket is of type ZMQ_XPUB and Client shall connect to it using ZMQ_SUB (or
ZMQ_XSUB).

Forwarder will publish subscription announcements in following format (note
that first byte '+', '-', '@', '!' is literally present in the message).
<+Topic> --- number of sinks + handlers for Topic grew above 0
<-Topic> --- number of sinks + handlers for Topic fell down to 0
<@QueryTopic|ResponseTopic> --- number of handlers responding on ResponseTopic
                                 for queries on QueryTopic grew above 0
<!QueryTopic|ResponseTopic> --- number of handlers responding on ResponseTopic
                                 for queries on QueryTopic fell down to 0

Messages received via Push socket will be republished by Forwarder in Sub socket
using following format:
<Topic|GlobalSequence|PublicId|MessageId|Body[|...]> where
 * GlobalSequence is value of GlobalSequenceType and will be incremented by 1 in
   each forwarded message which had valid size PrivateId (even if that message
   failed verification). Clients may use this sequnce number to ensure that they
   have not lost any intermediate message.
 * Other fields will be copied from message received in Push socket (but see
   details about verified and non verified messages below)

Forwarder performs validation of PrivateId, PublicId and MessageId. For messages
where this validation passed the only change from Push socket message will be
replacement of PrivateId with GlobalSequence. Therfore client may trust that
messages with:
 * valid size GlobalSequence part
 * valid size PublicId part
 * MessageId part starting with 'M', 'Q', 'R'
have headers verified by Forwarder as valid --- they were send by one of properly
registred clients (and in case of queries are being tracked --- i.e. Forwarder
will notify Sender of query if responder lost connection to Forwarder)

Such verified messages shall be always acted on by Client subscribed to given topic.

Handling of non-verified messages
====

It is up to the listening client to decide if non-verified messages will be
handled. For example a trivial case of Forwarder being restarted while Client
was connected to socket, and therefore Forwarder not being able to find out that
response sent by another client is a valid one, because Forwarder did not see
request sent by Client before Forwarder restart can be handled easily by Client
(i.e. it can analyze message with empty PrivateId, valid PublicId and MessageId
starting with 'r' instead of 'R' and detect that it is actually the response to
its own query, thanks to which it will be able to skip resending the query).
There may be also more complicated cases (e.g. known buggy client whose messages
can still be interpreted despite failing verification). Below is detailed
description of how Client can interpret message based on the first byte of
MessageId.

Fully verified message:
 'M', 'Q', 'R' --- message is verified, see Push socket documentation about
     what follows those bytes (note that MessageId field is being verified only
     if PrivateId and PublicId passed verification)

PrivateId and PublicId verified and MessageId started with valid marker, but
failed verification (only first byte of MessageId is modified):
 'q' --- Query cannot be tracked by Forwarder --- either there are no registered
     handlers (e.g. becuse they did not regegister after Forwarder restart yet)
     or there is bug in client (e.g. client used same sequence number before it
     received response for earlier query with that number)
 'r' --- response relates to query unknown to Forwarder --- most probably due to
     Forwarder restart between query and response, but client bug can also be a
     reason
 '^', '?', '#'  --- size of MessageId starting with 'M', 'Q', 'R' (respecively)
     was incorrect

Invalid MessageId first byte or invalid PrivateId and/or PublidcId:
 '&' --- Invalid MessageId first byte marker (neither of 'M', 'Q' nor 'R').
     This may happen only in case of bug in client. Full original MessageId
     follows '&' byte.
 '$' --- PublicId and/or PrivateId part was invalid, following bytes in MessageId are
     * one byte with integer value meaning
       0 --- both ids were of invalid size
       1 --- PrivateId had valid size but invalid value, PublicId had invalid size
       2 --- PublicId had valid size but invalid value, PrivateId had invalid size
       3 --- both ids had valid size but invalid value
     * valid size but invalid value PrivateId and/or PublicId (in that order)
       present if and only if indicated by previous byte (invalid sized ids are
       left intact in their original message parts)
     * original contents of MessageId

Notes about clients
====

Messages with first byte of MessageId being 'M', 'Q' or 'R' shall be treated as
verified and being tracked by forwarder and always acted by clients receiving
them. It is up to the listening client to decide if messages with any other
character in first byte of MessageId will be handled (and if yes if special
handling will be given to them). For example senders of queries shall consider
examining responses starting with 'r' to avoid resending same query only because
forwarder was restarted before response was generated (this may require to
remember old public id after RESET is received). Handlers which perform
read-only and low overhead operations may whish to respond to non-verified
queries (because sender of query may receive response even if frowarder was not
able to track it properly), but at the same time handlers which need to perform
write or high-overhead operations shall avoid handling non-verified messages
(unless they want to work around known bug in sender of the query), because well
behaving client will resend its query if the reason for non-verifiability was
forwarder restart.

)RAW_LITERAL";
#endif //1

	CommandLine(config::Data& data, int argc, char* argv[]) :
		CommonOptions(data, "Creates 3 zmq sockets to manage push/sub bus with req/rep functionality.")
	{
		bool zmq_help, dry_run;

		_named.add_options()
			("zmq-help,z", po::bool_switch(&zmq_help),
			 "print description of how sockets shall be used by clients")
			("dry-run",    po::bool_switch(&dry_run),
			 "do not start forwarder, but show what sockets would be used");

		parse(argc, argv);

		if (zmq_help)
		{
			_early_exit_needed=true;
			std::cout << long_help;
		}

		validate_common_options();

		if (dry_run)
		{
			std::cout << "dry-run count" << _vm.count("dry-run") << "\n";
			_early_exit_needed=true;
			std::cout << _out;
		}
		if (_early_exit_needed)
		{
			exit(0);
		}
	}

};

} //anonmymous namespace

Data parse_command_line(int argc, char* argv[])
{
	Data d;
	CommandLine(d, argc, argv);
	return d;
}

} // namepsace config
