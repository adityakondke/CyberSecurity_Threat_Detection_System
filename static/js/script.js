document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('container');
  const showRegisterBtn = document.getElementById('show-register');
  const showLoginBtn = document.getElementById('show-login');

  if (showRegisterBtn) {
    showRegisterBtn.addEventListener('click', () => {
      container.classList.add('active');
    });
  }

  if (showLoginBtn) {
    showLoginBtn.addEventListener('click', () => {
      container.classList.remove('active');
    });
  }
});



