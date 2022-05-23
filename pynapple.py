#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Pynapple IRC Client. Copyright 2013 Windsor Schmidt <windsor.schmidt@gmail.com>
#
# Notes/caveats:
#
# > doesn't handle large nick-lists (i.e. lists spanning multiple 353 messages)
#
# By the way, this line is 80 characters long....................................

import queue
from datetime import datetime
import hashlib
import socket
import string
import threading
import time
import argparse

from MonoAlphabeticSubstitution import MonoAlphabeticSubstitution
from Vigenere import Vigenere

from pynapple_tkui import *
#from pynapple_ncui import *

class IRC:
    # Encapsulates a connection to an IRC server. Handles sending / receiving of
    # messages, message parsing, connection and disconnection, etc.
    host="localhost"
    partMessage = "Parting!"
    quitMessage = "Quitting!"
    version = "0.0000001"
    nicklist = []
    connected = False
    joined = False
    logEnabled = False
    stopThreadRequest = threading.Event()
    rxQueue = queue.Queue()

    def __init__(self, 
                 attacker_key=None,
                 channel=None,
                 defender_key=None,
                 log_file="log.txt",
                 message_log_file="cyphered.txt",
                 name="Pynapple",
                 nick="pynapple", 
                 port=6667,
                 role="attacker",
                 server=None,
                 topic="",
                 user="pynapple"):
        """Constructor

        :nick: TODO
        :channel: TODO
        :server: TODO
        :topic: TODO
        :logfile: TODO
        :returns: TODO

        """
        self.nick = nick
        self.channel = channel
        self.server = server
        self.port = port
        self.topic = topic
        self.user = user
        self.name = name
        self.log_file = log_file
        self.message_log_file = message_log_file
        self.role = role
        if attacker_key is not None:
            self.monosub = MonoAlphabeticSubstitution(attacker_key)
        else:
            self.monosub = MonoAlphabeticSubstitution("abcdefghijklmnopqrstuvwxyz")

        if defender_key is not None:
            self.vigenere = Vigenere(defender_key)
        else:
            self.vigenere = Vigenere("z")

        if self.server is not None:
            self.connect(self.server, self.port)
            if self.channel is not None:
                self.join(self.channel)

        if message_log_file is not None:
            self.message_fd = open(message_log_file, "a")
            self.cyphered_logging = True
        else:
            self.cyphered_logging = False


    def start_thread(self):
        # Spawn a new thread to handle incoming data. This function expects that
        # the class variable named socket is a handle to a currently open socket.
        self.socketThread = SocketThread(self.stopThreadRequest,
                                         self.rxQueue,
                                         self.server,
                                         self.port,
                                         self.sock)
        self.stopThreadRequest.clear()
        self.socketThread.start()

    def stop_thread(self):
        # Signal the socket thread to terminate by setting a shared event flag.
        self.stopThreadRequest.set()

    def print_status(self, message):
        try:
            ui.add_status_message(message)
        except:
            print(message)

    def print_debug(self, message):
        try:
            ui.add_debug_message(message)
        except:
            print("DEBUG: " + message)
        

    def connect(self, server, port):
        # Connect to an IRC server using a given host name and port. Creates a
        # network socket that is used by a separate thread when receiving data.
        if (not self.connected):
            self.server = server
            self.port = port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server, self.port))
            self.start_thread()
            self.print_status("connecting to %s:%s" % (server, str(port)))
            self.connected = True
            self.login(self.nick, self.user, self.name, self.host, server)
        else:
            self.print_status("already connected")

    def send(self, command):
        # Send data to a connected IRC server.
        if (self.connected):
            self.sock.send(bytes(command + '\n', 'UTF-8'))
            self.print_debug("-> " + command)

    def send_message(self, s):
        # Send a message to the currently joined channel.
        if (self.joined):
            if self.role == "attacker":
                ui.add_nick_message("Private", s)
                cyphered = self.monosub.cypher(s)
            elif self.role == "defender":
                ui.add_nick_message("Private", s)
                cyphered = self.vigenere.cypher(s)
            else:
                cyphered = s
            m = "%s <-> %s" % (self.role, cyphered)
            ui.add_nick_message(self.get_nick(), m)
            self.send("PRIVMSG %s :%s" % (self.channel, m))
        else:
            self.print_status("not in a channel")

    def send_private_message(self, nick, s):
        # Send a private message to the given nickname.
        if (self.connected):
            self.send("PRIVMSG %s :%s" % (nick, s))
            ui.add_nick_message(self.get_nick(), "[%s] %s" % (nick, s))
        else:
            self.print_status("not connected")

    def get_status(self):
        return (self.nick, self.server, self.channel, self.topic)

    def disconnect(self):
        # Disconnect from the currently connected IRC server.
        if (self.connected):
            self.send("QUIT :%s" % self.quitMessage)
            self.stop_thread()
            self.connected = False
            self.server = ""
            self.print_status("disconnected")
            ui.update_status()
            if self.cyphered_logging:
                self.message_fd.close()
        else:
            self.print_status("not connected")

    def login(self, nick, user, name, host, server):
        # Send a log-in stanza to the currently connected server.
        self.send("USER %s %s %s %s" % (user, host, server, name))
        self.send("NICK %s" % nick)
        self.print_status("using nickname %s" % nick)

    def join(self, channel):
        # Join the given channel.
        if (self.connected):
            if (not self.joined):
                self.send("JOIN %s" % channel)
            else:
                self.print_status("already in a channel")
        else:
            self.print_status("not connected")

    def part(self):
        # Leave the current channel.
        if (self.joined):
            self.send("PART %s" % self.channel)
            self.set_nicklist([])
            self.print_status("left channel %s " % self.channel)
            self.joined = False
            self.channel = ""
            ui.update_status()
        else:
            self.print_status("not in a channel")

    def add_nick(self, s):
        # Add a nickname to the list of nicknames we think are in the channel.
        # Called when a user joins the current channel, in response to a join.
        self.nicklist.append(s)
        self.nicklist.sort()
        ui.set_nicklist(self.nicklist)

    def del_nick(self, s):
        # Remove a nickname the list of nicknames we think are in the channel.
        if s in self.nicklist:
            self.nicklist.remove(s)
            ui.set_nicklist(self.nicklist)

    def replace_nick(self, old, new):
        self.del_nick(old)
        self.add_nick(new)
        ui.set_nicklist(self.nicklist)
        self.print_status("%s is now known as %s" % (old, new))

    def request_nicklist(self):
        # Send a request to the IRC server to give us a list of nicknames
        # visible in the current channel.
        if (self.joined):
            self.send("NAMES %s" % self.channel)

    def set_nicklist(self, a):
        # Replace the list of nicknames with the list given.
        self.nicklist = a
        ui.set_nicklist(self.nicklist)

    def set_nick(self, s):
        # Change our own nickname.
        if (self.connected):
            self.send(":%s!%s@%s NICK %s" % (self.nick, self.user, self.host, s))

    def get_nick(self):
        # Return our own nickname.
        return self.nick

    def get_channel(self):
        # Return the name of the currently joined channel.
        if (self.joined):
            return self.channel
        else:
            return "~"

    def is_connected(self):
        # Return our IRC server connection state.
        return self.connected

    def handle_ctcp(self, cmd, msg):
        self.print_status("got CTCP message: " + cmd)
        if (cmd == "VERSION"):
            self.send("VERSION pynapple-irc %s" % self.version)
        if (cmd == "ACTION"):
            ui.add_emote_message(self.nick, msg)

    def get_version(self):
        return self.version

    def logToFile(self, s):
        # Write the given string to a log file on disk, appending a newline.
        # The logfile is opened for writing if not already open.
        if (not self.logEnabled):
            self.logEnabled = True
            self.file = open(self.log_file, 'w')
        self.file.write(s + "\n")
        self.file.flush()

    def poll(self):
        # Check for incoming messages from the IRC server by polling a shared
        # message-queue populated by the socket handling thread. Strings read
        # from the queue have been buffered from the receiving socket and each
        # string represents a logical message sent by the server.
        rx = ""
        try:
            rx = self.rxQueue.get(True, 0.01)
        except:
            pass
        if (rx != ""):
            self.print_debug("<- " + rx)
            self.logToFile(rx)
            self.handle_message(self.parse_message(rx))

    def parse_message(self, s):
        # Transform incoming message strings received by the IRC server in to
        # component parts common to all messages.
        prefix = ''
        trailing = []
        if (s[0] == ':'):
            prefix, s = s[1:].split(' ', 1)
        if (s.find(' :')) != -1:
            s, trailing = s.split(' :', 1)
            args = s.split()
            args.append(trailing)
        else:
            args = s.split()
        command = args.pop(0)
        return prefix, command, args

    def handle_message(self, msg):
        # Respond to incoming IRC messages by handling them here or passing
        # control to other class methods for further processing.
        prefix, cmd, args = msg
        if (cmd == "PING"):
            # Reply to PING, per RFC 1459 otherwise we'll get disconnected.
            self.send("PONG %s" % args[0])
        if (cmd == "PRIVMSG"):
            # Either a channel message or a private message; check and display.
            message = ' '.join(args[1:])
            nick = prefix[:prefix.find('!')]
            if (args[1].startswith(chr(1))):
                ctcp = message.translate(None, chr(1)).split()
                ctcp_cmd = ctcp[0]
                ctcp_msg = ' '.join(ctcp[1:])
                self.handle_ctcp(ctcp_cmd, ctcp_msg)
            elif (args[0] == self.channel):
                try:
                    role, content = message.split(" <-> ")
                    if role == "attacker":
                        dc = self.monosub.decypher(content)
                        message = "%s <-> %s" % (role, dc)
                    elif role == "defender":
                        dc = self.vigenere.decypher(content)
                        message = "%s <-> %s" % (role, dc)
                    if self.cyphered_logging and role != self.role:
                        print(content, file=self.message_fd)
                        self.message_fd.flush()
                except:
                    pass
                ui.add_nick_message(nick, message)
            else:
                ui.add_private_message(nick, message)
        if (cmd == "JOIN"):
            nick = prefix[:prefix.find('!')]
            if (not self.joined):
                # We weren't joined, so join message must be us joining.
                self.joined = True
                self.channel = args[0]
                ui.update_status()
                self.print_status("joined channel %s " % self.channel)
            elif (nick != self.nick):
                # A user has joined the channel. Update nick list.
                self.add_nick(prefix[:prefix.find('!')])
                self.print_status("%s joined the channel" % nick)
        if (cmd == "PART" and args[0] == self.channel):
            # A user has left the channel. Update nick list.
            nick = prefix[:prefix.find('!')]
            self.del_nick(nick)
            self.print_status("%s left the channel" % nick)
        if (cmd == "353"):
            # Receiving a list of users in the channel (aka RPL_NAMEREPLY).
            # Note that the user list may span multiple 353 messages.
            nicklist = ' '.join(args[3:]).split()
            self.set_nicklist(nicklist)
        if (cmd == "376"):
            # Finished receiving the message of the day (MOTD).
            self.print_status("MOTD received, ready for action")
            ui.update_status()
        if (cmd == "NICK"):
            old = prefix[:prefix.find('!')]
            new = args[0]
            if (old == self.nick):
                # server acknowledges we changed our own nick
                self.nick = new
            self.replace_nick(old, new)
            ui.update_status()

class SocketThread(threading.Thread):
    # A worker thread used to receive data from the connected IRC server. Once
    # started, sits in a loop reading data and assembling line-based messages
    # from the server. This thread terminates after a shared status flag is set
    # by the main thread in response to a disconnect command.
    running = True
    def __init__(self, event, rxQueue, server, port, sock):
        super(SocketThread, self).__init__()
        self.stopThreadRequest = event
        self.rxQueue = rxQueue
        self.server = server
        self.port = port
        self.sock = sock

    def run(self):
        # Continuously read from our (blocking) socket. We want to add complete
        # messages from the IRC server to our queue to be handled downstream, but
        # since the network buffer may contain only part of a message, we'll use
        # a local buffer to store incomplete messages.
        rx = ""
        while(not self.stopThreadRequest.isSet()):
            rx = rx + self.sock.recv(1024).decode("utf-8")
            if (rx != ""):
                temp = rx.split("\n")
                rx = temp.pop( ) # put left-over data back in our local buffer
                for line in temp:
                    line = line.rstrip()
                    self.rxQueue.put(line)
            else:
                # remote end disconnected, so commit thread suicide!
                self.stopThreadRequest.set()
        return

class UserInterface:
    # Uses the curses terminal handling library to display a chat log,
    # a list of users in the current channel, and a command prompt for
    # entering messages and application commands.
    badwords = []
    hilites = []
    def __init__(self, irc_instance, keyboard_handler):
        self.badwords = self.load_list("badwords.txt")
        self.hilites = self.load_list("hilites.txt")
        self.uiPlugin = UserInterfacePlugin(irc_instance,
                                            keyboard_handler)
        self.colors = self.uiPlugin.get_max_colors()
        self.draw_pineapple()
        self.add_status_message("welcome to pynapple-irc v" + irc.get_version())
        self.add_status_message("type /help for a list of commands")

    def run(self):
        self.uiPlugin.run()

    def add_message(self, s, color, hilite):
        msgtxt = self.censor(s)
        msg = self.time_stamp() + " " + msgtxt
        self.uiPlugin.add_message(msg, color, hilite)

    def add_nick_message(self, nick, s):
        # Add another user's message in the chat window.
        color = self.get_nick_color(nick)
        hilite = False
        if (nick != irc.get_nick()):
            hilite = self.hilite(s)
        self.add_message("<" + nick + "> " + s, color, hilite)

    def add_emote_message(self, nick, s):
        # Add another user's "emoted" message in the chat window.
        color = self.get_nick_color(nick)
        if (nick != irc.get_nick()):
            hilite = self.hilite(s)
        self.add_message("* " + nick + " " + s, color, hilite)

    def add_private_message(self, nick, s):
        # Add another user's private message in the chat window.
        self.add_nick_message(nick, "[private] " + s)

    def add_status_message(self, s):
        # Add a status message in the chat window.
        self.add_message("== " + s, 7, False)

    def add_debug_message(self, s):
        self.uiPlugin.add_debug_message(s)

    def hilite(self, s):
        # Return an true if the given word matches our highlight list.
        # The attribute is combined with any other attributes (e.g. colors)
        # when printing string. It is typical for IRC clients to highlight
        # incoming messages containing our own nick.
        if any(w in s for w in self.hilites + [irc.get_nick()]):
            return True
        else:
            return False

    def set_nicklist(self, a):
        # Populate the nick-list with an alphabetically sorted array of nicks.
        self.uiPlugin.set_nicklist(a)

    def init_colors(self):
        self.uiPlugin.init_colors()

    def get_nick_color(self, s):
        # It is often helpful to color messages based on the nick of the message
        # sender. Map an input string (the nick) to a color ID using Python's
        # hashing functions. The modulo operator here is used to map the hash
        # output value to a range within bounds of the color look up table.
        return(int(hashlib.md5(s.encode('utf-8')).hexdigest(), 16) % self.colors)

    def shutdown(self):
        self.uiPlugin.shutdown()

    def toggle_debug(self):
        self.uiPlugin.toggle_debug()

    def draw_pineapple(self):
        # Draw a sweet ASCII art rendition of a pinapple. Come to think of it,
        # it has been getting increasingly difficult to type the word pinapple
        # without replacing the "i" with a "y" instead.
        self.add_message("                \\\\//", 2, False)
        self.add_message("                \\\\//", 2, False)
        self.add_message("                \\\\//", 2, False)
        self.add_message("                /..\\", 3, False)
        self.add_message("                |..|", 3, False)
        self.add_message("                \\__/", 3, False)

    def time_stamp(self):
        # Generate a string containing the current time, used to prefix messages.
        return datetime.now().strftime("[%H:%M]")

    def load_list(self, s):
        # A utility function that loads each line from a given file in to a list.
        try:
            with open(s) as f:
                lines = f.readlines()
                f.close()
        except IOError:
            return []
        return [x.strip() for x in lines]

    def censor(self, s):
        # Replace bad words with an equal length string of asterisks
        for tag in self.badwords:
            s = s.replace(tag, "*" * len(tag))
        return s

    def update_status(self):
        self.uiPlugin.update_status()

class KeyboardHandler:
    lastInput = ""
    def parse_input(self, s):
        # Parse local user input and handle by dispatching commands or sending
        # messages to the current IRC channel.
        if ((s == "/") and (self.lastInput != "")):
            # Protip: Re-use the last input if a single forward slash is entered.
            s = self.lastInput
        self.lastInput = s
        if (s[0] == '/'):
            if (len(s) > 1):
                # got a command; handle locally,
                self.handle_cmd(s[1:])
        else:
            # otherwise send input as a channel message
            irc.send_message(s)

    def handle_cmd(self, s):
        # Respond to a command string intended to be processed locally.
        cmd = s.split()[0]
        args = s.split()[1:]
        if (cmd == "connect"):
            # Connect to the given IRC server.
            if (len(args) == 1) and (args[0].count(":") == 1):
                server, port = args[0].split(':')
                if not len(port):
                    port="6667"
                if port.isdigit():
                    irc.print_status("connecting to " + server + ":" + port)
                    irc.connect(server, int(port))
                else:
                    irc.print_status("port must be specified as an integer")
            else:
                irc.print_status("usage: connect <server:port>")
        elif (cmd == "disconnect"):
            # Disconnect from the current IRC server.
            irc.part()
            irc.disconnect()
        elif (cmd == "join"):
            # Join the given channel.
            if (len(args) < 1):
                irc.print_status("usage: join <channel>")
            else:
                irc.join(args[0])
        elif (cmd == "part"):
            # Leave the current channel.
            irc.part()
        elif (cmd == "msg"):
            # Send a private message to the given user.
            if (len(args) < 2):
                irc.print_status("usage: msg <nick> <message>")
            else:
                msg = ' '.join(args[1:])
                irc.send_private_message(args[0], msg)
        elif (cmd == "nick"):
            if (len(args) < 1):
                irc.print_status("usage: nick <new nick>")
            else:
                irc.set_nick(args[0])
        elif (cmd == "debug"):
            # Show or hide the debug window.
            ui.toggle_debug()
        elif (cmd == "names"):
            # Ask server for a list of nicks in the channel. TODO: Remove this.
            irc.request_nicklist()
        elif (cmd == "help"):
            # Print a list of commands.
            irc.print_status("available commands:")
            irc.print_status("/connect <server:port>")
            irc.print_status("/disconnect")
            irc.print_status("/join <channel>")
            irc.print_status("/part")
            irc.print_status("/msg <nick> <message>")
            irc.print_status("/nick <new nick>")
            irc.print_status("/quit")
        elif (cmd == "quit"):
            # Quit the program.
            irc.part()
            irc.disconnect()
            ui.shutdown()
            exit()
        elif (cmd == "test"):
            irc.connect("localhost", 6667)
            irc.join("#pynapple")
        else:
            # The user entered an unknown command, punish them!
            msg = "unknown command: " + cmd
            irc.print_status(msg)
        self.lastCommandString = s

# Argument parsing
parser = argparse.ArgumentParser(description="Set parameters for irc client")

parser.add_argument("-a", "--attacker-key", 
                    help="Specify attacker cypher key", default=None)
parser.add_argument("-d", "--defender-key", 
                    help="Specify defender cypher key", default=None)
parser.add_argument("-c", "--channel", 
                    help="Specify a channel to connect to", 
                    default="#pynapple")
parser.add_argument("-l", "--log", help="Specify logfile",
                    default="log.txt")
parser.add_argument("-L", "--message-log-file", 
                    help="Specify a file that will contain all the encrypted messages", 
                    default="cyphered.log")
parser.add_argument("-n", "--nick", help="Specify IRC nickname",
                    default="pynapple")
parser.add_argument("-N", "--name", help="Specify user real name",
                    default="Pynapple User")
parser.add_argument("-p", "--port", 
                    help="Specify port on which server is listening", 
                    type=int, default=6667)
parser.add_argument("-r", "--role", help="Specify attacker or defender", 
                    default="attacker",
                    choices=["attacker", "defender"])
parser.add_argument("-s", "--server", 
                    help="Specify a server to connect to", 
                    default="irc.libera.chat")
parser.add_argument("-u", "--user", help="Specify user name",
                    default="pynapple")

args = parser.parse_args()

if args.channel and args.channel[0] != '#':
    args.channel = '#' + args.channel

irc = IRC(attacker_key=args.attacker_key,
          channel=args.channel,
          defender_key=args.defender_key,
          log_file=args.log,
          message_log_file=args.message_log_file,
          name=args.name, 
          nick=args.nick, 
          port=args.port,
          role=args.role,
          server=args.server,
          user=args.user)

kb = KeyboardHandler()
ui = UserInterface(irc_instance=irc, keyboard_handler=kb)
ui.run()
