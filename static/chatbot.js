// Chatbot functionality
const chatContainer = document.getElementById('chat-container');
const chatLog = document.getElementById('chat-log');
const userInput = document.getElementById('user-input');

// Toggle Chat Window visibility
function toggleChat() {
    chatContainer.style.display = (chatContainer.style.display === "none" || chatContainer.style.display === "") ? "flex" : "none";
}

// Send Message
function sendMessage() {
    const message = userInput.value.trim();
    if (message === "") return;

    displayMessage(message, true); // Display user message

    fetch('/chatbot', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'query=' + encodeURIComponent(message),
    })
    .then(response => response.json())
    .then(data => {
        displayMessage(data.response, false); // Display bot response
    })
    .catch(error => {
        console.error('Error:', error);
        displayMessage("Error processing request.", false);
    });

    userInput.value = ''; // Clear input field
}

// Display Message in Chat Log
function displayMessage(message, isUser) {
    const messageDiv = document.createElement('div');
    messageDiv.textContent = (isUser ? "You: " : "Bot: ") + message;
    chatLog.appendChild(messageDiv);
    chatLog.scrollTop = chatLog.scrollHeight; // Auto-scroll
}

// Send message on Enter key press
userInput.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        sendMessage();
    }
});
