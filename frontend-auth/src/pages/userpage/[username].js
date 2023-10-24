import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

function UserPage() {
  const router = useRouter();
  const { username } = router.query; // getting username from the route parameter
  const [message, setMessage] = useState('');
  const [jwtToken, setJwtToken] = useState('');

  useEffect(() => {
    const token = localStorage.getItem("jwt");
    setJwtToken(token);

    if (username && jwtToken) {
      fetch(`https://localhost:2000/userpage/${encodeURIComponent(username)}`, {
        headers: {
          'Authorization': `Bearer ${jwtToken}`
        }
      })
        .then(response => {
          if (!response.ok) {
            throw new Error('Network response was not ok');
          }
          return response.text(); // or response.json() if your server returns JSON
        })
        .then(data => {
          setMessage(data);
        })
        .catch(error => {
          console.error('There has been a problem with your fetch operation:', error);
        });
    }
  }, [username]); // This effect runs when the "username" changes

  return (
    <div>
      <h1>User: {username}</h1>
      <p>{message}</p>
    </div>
  );
}

export default UserPage;
