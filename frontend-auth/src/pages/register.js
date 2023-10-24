import React, { useState } from 'react';
import axios from 'axios';

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const registerUser = async () => {
    try {
      const response = await axios.post('https://localhost:2000/register', {
        username: username,
        password: password
      });
      setMessage(response.data.message);
    } catch (error) {
      setMessage('Registration failed.');
    }
  };

  return (
    <div className="container">
      <h2>Register</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={registerUser}>Register</button>
      {message && <p>{message}</p>}
    </div>
  );
};

export default Register;
