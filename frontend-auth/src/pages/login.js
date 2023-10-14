import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const loginUser = async () => {
    try {
      const response = await axios.post('http://localhost:2000/login', {
        username: username,
        password: password
      });
      if (response.data.token) {
        localStorage.setItem('jwt', response.data.token);
      }
      setMessage(response.data.message);
    } catch (error) {
      setMessage('Login failed.');
    }
  };

  return (
    <div className="container">
      <h2>Login</h2>
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
      <button onClick={loginUser}>Login</button>
      {message && <p>{message}</p>}
    </div>
  );
};

export default Login;
