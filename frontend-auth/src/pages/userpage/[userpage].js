import { useState, useEffect } from 'react';

function UserPage() {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {

    const jwtToken = localStorage.getItem('jwt');

    // Fetch data from the Flask endpoint
    fetch('http://localhost:2000/userpage-test', {
      headers: {
        'Authorization': `Bearer ${jwtToken}`
      }
    })
      .then((response) => response.json())
      .then((data) => {
        setMessage(data.message);
        setLoading(false);
      })
      .catch((error) => {
        setMessage('Failed to fetch data from the backend.');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="container">
      <h1>User Page</h1>
      <p>{message}</p>
    </div>
  );
}

export default UserPage;
