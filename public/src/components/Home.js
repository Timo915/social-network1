// Home.js
import React, { useState } from 'react';
import { View, TextInput, Button, FlatList, Text } from 'react-native';

const Home = ({ navigation }) => {
  const [search, setSearch] = useState('');
  const [users, setUsers] = useState([]); // Массив пользователей

  const handleSearch = () => {
    // Отправить запрос на поиск пользователей на сервер
  };

  return (
    <View>
      <TextInput 
        placeholder="Search Users" 
        value={search} 
        onChangeText={setSearch} 
      />
      <Button title="Search" onPress={handleSearch} />
      <FlatList 
        data={users} 
        renderItem={({ item }) => (
          <Text onPress={() => navigation.navigate('Chat', { userId: item.id })}>{item.username}</Text>
        )}
      />
    </View>
  );
};

export default Home;