document.addEventListener('DOMContentLoaded', function () {
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const passwordStrengthSpan = document.getElementById('password-strength');
    const passwordMatchSpan = document.getElementById('password-match');
    const registerButton = document.querySelector('button[type="submit"]');

    // Function to check password strength
    function checkPasswordStrength(password) {
        // Regular expressions to check for capital letter, small letter, and special character
        const hasCapitalLetter = /[A-Z]/.test(password);
        const hasSmallLetter = /[a-z]/.test(password);
        const hasSpecialCharacter = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password);

        // Check if the password meets the criteria
        return password.length >= 8 && hasCapitalLetter && hasSmallLetter && hasSpecialCharacter;
    }

    // Add event listener for input event on the password input field
    newPasswordInput.addEventListener('input', function () {
        const password = newPasswordInput.value;

        // Check password strength
        if (checkPasswordStrength(password)) {
            passwordStrengthSpan.textContent = 'Password strength: Strong';
            passwordStrengthSpan.style.color = 'green';
        } else {
            passwordStrengthSpan.textContent = 'Password strength: Weak';
            passwordStrengthSpan.style.color = 'red';
        }

        // Check if both password and confirm password match, and enable/disable the register button accordingly
        if (password === confirmPasswordInput.value && checkPasswordStrength(password)) {
            registerButton.disabled = false;
            registerButton.classList.remove('disabled');
        } else {
            registerButton.disabled = true;
            registerButton.classList.add('disabled');
        }
    });

    // Function to check if the password and confirm password fields match
    function checkPasswordMatch() {
        const password = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        // Check if the passwords match and the password strength is strong
        if (password === confirmPassword) {
            // Set the text content and color of the password match span
            passwordMatchSpan.textContent = 'Passwords match';
            passwordMatchSpan.style.color = 'green';
            registerButton.disabled = false;
            registerButton.classList.remove('disabled');
        } else {
            // Set the text content and color of the password match span
            passwordMatchSpan.textContent = 'Passwords do not match';
            passwordMatchSpan.style.color = 'red';
            registerButton.disabled = true;
            registerButton.classList.add('disabled');
        }
    }

    // Event listener to check password match on input in the confirm password field
    confirmPasswordInput.addEventListener('input', checkPasswordMatch);
});



function fadeOutFlashMessage() {
    const messageElement = document.querySelector('.flash-message'); // Adjust selector for your message element

    if (messageElement) {
        messageElement.classList.add('fadeOut'); // Add a CSS class for fading

        setTimeout(() => {
            messageElement.remove(); // Remove the element after fading
        }, 3000);
    }
}

window.onload = fadeOutFlashMessage;

const closeButton = document.querySelector('.close-button');

if (closeButton) {
    closeButton.addEventListener('click', fadeOutFlashMessage);
}
function dashboard() {
    window.location.href = "/dashboard";
}
function logout(){
    window.location.href = "/logout"
}
