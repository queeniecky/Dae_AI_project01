document.addEventListener('DOMContentLoaded', () => {
  const registerForm = document.getElementById('register');
  const loginForm = document.getElementById('login');
  const logout = document.getElementById('logout');
  const protectedContent = document.getElementById('protectedContent');
  const updateEmailForm = document.getElementById('updateEmailForm');

  // Register form submission
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('regUsername').value;
      const email = document.getElementById('regEmail').value;
      const password = document.getElementById('regPassword').value;

      try {
        const response = await fetch('http://localhost:3000/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, password })
        });
        const data = await response.json();
        
        if (response.ok) {
          alert(data.message);
          registerForm.reset();
          window.location.href = '/login.html';
        } else {
          alert(data.error);
        }
      } catch (error) {
        alert('網絡錯誤');
      }
    });
  }

  // Login form submission
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;

      try {
        const response = await fetch('http://localhost:3000/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (response.ok) {
          localStorage.setItem('token', data.token);
          window.location.href = data.redirectTo || '/dashboard.html';
        } else {
          alert(data.error);
        }
      } catch (error) {
        alert('網絡錯誤');
      }
    });
  }

  // Update email form submission
  if (updateEmailForm) {
    updateEmailForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newEmail = document.getElementById('newEmail').value;
      const token = localStorage.getItem('token');

      if (!token) {
        alert('請先登入');
        window.location.href = '/login.html';
        return;
      }

      try {
        const response = await fetch('http://localhost:3000/api/update-email', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ email: newEmail })
        });
        const data = await response.json();

        if (response.ok) {
          alert(data.message);
          updateEmailForm.reset();
          showProtectedContent(); // Refresh user info
        } else {
          alert(data.error);
        }
      } catch (error) {
        alert('網絡錯誤');
      }
    });
  }

  // Logout
  if (logout) {
    logout.addEventListener('click', () => {
      localStorage.removeItem('token');
      window.location.href = '/index.html';
    });
  }

  // Show protected content (for index.html and dashboard.html)
  async function showProtectedContent() {
    const token = localStorage.getItem('token');
    if (!token || !protectedContent) return;

    try {
      const response = await fetch('http://localhost:3000/api/protected', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();

      if (response.ok) {
        document.getElementById('welcomeContent')?.classList.add('hidden');
        protectedContent.classList.remove('hidden');
        const userInfo = document.getElementById('userInfo');
        if (userInfo) {
          userInfo.textContent = window.location.pathname.includes('dashboard.html')
            ? `用戶名: ${data.user.username}, 郵箱: ${data.user.email}`
            : `歡迎，${data.user.username}!`;
        }
      } else {
        localStorage.removeItem('token');
        document.getElementById('welcomeContent')?.classList.remove('hidden');
        protectedContent.classList.add('hidden');
      }
    } catch (error) {
      localStorage.removeItem('token');
      document.getElementById('welcomeContent')?.classList.remove('hidden');
      protectedContent.classList.add('hidden');
    }
  }

  // Check token on page load (for index.html and dashboard.html)
  if (window.location.pathname === '/index.html' || window.location.pathname === '/' || window.location.pathname === '/dashboard.html') {
    showProtectedContent();
  }
});