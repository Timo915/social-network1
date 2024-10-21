// Register.js
import React, { useState } from 'react';
import { View, TextInput, Button, Text } from 'react-native';

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleRegister = () => {
    // Отправить запрос на сервер для регистрации
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
      <Button title="Register" onPress={handleRegister} />
    </View>
  );
};

export default Register;