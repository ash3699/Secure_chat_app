Task3:

Move the contents of the Task3 folder to home/ubuntu/secure_chat_app/task3 directory in all 3 containers (alice1, bob1, trudy1)
1. In the home/ubuntu/secure_chat_app/task3 directory in the container trudy1 compile the file secure_chat_interceptor.cpp using the command:
    g++ secure_chat_interceptor.cpp -o secure_chat_interceptor

2. In the assigned VM run the poison-dns-alice1-bob1.sh script using the following command:
    bash ~/poison-dns-alice1-bob1.sh

    This will make alice1 and bob1 connect to trudy1's IP address when they try to connect to each other.

3. Go to the home/ubuntu/secure_chat_app/task3 directory in the containers alice1 and bob1 respectively and compile the code secure_chat_app.cpp in both using the command:
    g++ secure_chat_app.cpp -o secure_chat_app

4. Run the secure_chat_app in the bob1 container using the following command:
    ./secure_chat_app -s

    This will run the secure_chat_app as server on the container bob1

5. Run the secure_chat_interceptor in the trudy1 container using the following command:
    ./secure_chat_interceptor -d alice1 bob1

    This will run the secure_chat_interceptor as attacker/interceptor on the container trudy1 and try to intercept the messages sent and receieved from the IP addresses associated with the hostname alice1 and bob1. Trudy will depreciate the security by intercepting the chat_START_SSL from Alice and instead of transmitting it to bob it will reply with chat_START_SSL_NOT_SUPPORTED message which prevents establishment of TLS connection and forces Alice and Bob to continue with the unsecure UDP connection.

6. Run the secure_chat_app in the alice1 container using the following command:
    ./secure_chat_app -c bob1

    This will run the secure_chat_app as client on the container alice1 and try to connect to the IP associated with the hostname bob1


