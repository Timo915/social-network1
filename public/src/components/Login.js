// Login.js
import React, { useState } from 'react';
import { View, TextInput, Button, Text } from 'react-native';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = () => {
    // Отправить запрос на сервер для аутентификации
  };

  return (
    <View>
      <TextInput 
        placeholder="Username" 
        value={username} 
        onChangeText={setUsername} 
      />
      <TextInput 
        placeholder="Password" 
        secureTextEntry 
        value={password} 
        onChangeText={setPassword} 
      />
      <Button title="Login" onPress={handleLogin} />
    </View>
  );
};

export default Login;