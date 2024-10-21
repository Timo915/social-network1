// Chat.js
import React, { useEffect, useState } from 'react';
import { View, TextInput, Button, FlatList, Text } from 'react-native';
import io from 'socket.io-client';

const Chat = ({ route }) => {
  const { userId } = route.params;
  const [messages, setMessages] = useState([]);
  const [message, setMessage] = useState('');
  const socket = io('http://localhost:5000'); // Укажите свой сервер

  useEffect(() => {
    socket.on('receiveMessage', (msg) => {
      setMessages((prevMessages) => [...prevMessages, msg]);
    });

    return () => {
      socket.off('receiveMessage');
    };
  }, []);

  const sendMessage = () => {
    socket.emit('sendMessage', { userId, message });
    setMessage('');
  };

  return (
    <View>
      <FlatList 
        data={messages} 
        renderItem={({ item }) => <Text>{item}</Text>} 
      />
      <TextInput 
        value={message} 
        onChangeText={setMessage} 
        placeholder="Type your message" 
      />
      <Button title="Send" onPress={sendMessage} />
    </View>
  );
};

export default Chat;