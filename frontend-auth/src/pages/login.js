import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const loginUser = async () => {
    try {
      // Starting the fetch request.
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      const response = await fetch('https://localhost:2000/login', {
        method: 'POST', // Specifying the method
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json', // Specifying content type as JSON
        },
        body: JSON.stringify({ // Sending the body as stringified JSON
          username: username,
          password: password,
        }),
      });
  
      // Fetch doesn't reject the promise on HTTP error status (even 404 or 500),
      // so we need to manually catch them.
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
  
      // Proceed to parse the response as JSON
      const data = await response.json();
  
      // Assuming the token is sent back on a successful login
      if (data.token) {
        console.log(data);
        localStorage.setItem('jwt', data.token); // Storing the token in local storage
      }
  
      // Set the message to indicate a successful operation
      setMessage(data.message);
    } catch (error) {
      // Catching an error during the fetch call
      console.error("There was a problem with the login request: ", error);
  
      // Setting the message to indicate a failed operation
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
