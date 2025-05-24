document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const scanProgress = document.getElementById('scanProgress');
    const error = document.getElementById('error');

    // Show progress indicator when form is submitted (even with regular form submission)
    if (scanForm) {
        scanForm.addEventListener('submit', function() {
            // Reset and show progress
            if (error) error.classList.add('d-none');
            scanProgress.classList.remove('d-none');
        });
    }
});

     // Chatbot Functionality
    const chatbotToggle = document.getElementById("chatbotToggle");
    const chatbotWindow = document.getElementById("chatbotWindow");
    const chatbotClose = document.getElementById("chatbotClose");
    const chatbotClear = document.getElementById("chatbotClear");
    const chatbotForm = document.getElementById("chatbotForm");
    const chatbotMessages = document.getElementById("chatbotMessages");
    const chatbotInput = document.getElementById("chatbotInput");

    // Replace with your Gemini API key (for testing only)
    const GEMINI_API_KEY = "AIzaSyAbITcuMjb_NSO9PjfaXI6SBICMVRlqrlI"; // Secure this in production

    // Initialize conversation history
    let conversationHistory = [
      {
        role: "model",
        parts: [{ text: "Hello! I'm your security assistant. How can I assist you with security scanning?" }]
      }
    ];

    // Toggle chatbot window
    chatbotToggle.addEventListener("click", () => {
      chatbotWindow.style.display = chatbotWindow.style.display === "flex" ? "none" : "flex";
    });
    chatbotClose.addEventListener("click", () => {
      chatbotWindow.style.display = "none";
    });

    // Clear chat history
    chatbotClear.addEventListener("click", () => {
      conversationHistory = [
        {
          role: "model",
          parts: [{ text: "Hello! I'm jok. How can I assist you?" }]
        }
      ];
      chatbotMessages.innerHTML = '<div class="chatbot-message bot">Hello! I\'m security assistant. How can I assist you?</div>';
    });

    // Handle chatbot form submission
    chatbotForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const message = chatbotInput.value.trim();
      if (!message) return;

      // Add user message to UI
      const userMessage = document.createElement("div");
      userMessage.className = "chatbot-message user";
      userMessage.textContent = message;
      chatbotMessages.appendChild(userMessage);

      // Add user message to history
      conversationHistory.push({
        role: "user",
        parts: [{ text: message }]
      });

      // Clear input
      chatbotInput.value = "";

      // Scroll to bottom
      chatbotMessages.scrollTop = chatbotMessages.scrollHeight;

      // Call Gemini API
      try {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              contents: conversationHistory
            })
          }
        );

        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        const botResponse = data.candidates[0].content.parts[0].text || "Sorry, I couldn't process that.";

        // Add bot response to UI
        const botMessage = document.createElement("div");
        botMessage.className = "chatbot-message bot";
        botMessage.textContent = botResponse;
        chatbotMessages.appendChild(botMessage);
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;

        // Add bot response to history
        conversationHistory.push({
          role: "model",
          parts: [{ text: botResponse }]
        });
      } catch (error) {
        console.error("Gemini API error:", error);
        const botMessage = document.createElement("div");
        botMessage.className = "chatbot-message bot";
        botMessage.textContent = "Oops, something went wrong. Please try again later.";
        chatbotMessages.appendChild(botMessage);
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;

        // Add error message to history to maintain context
        conversationHistory.push({
          role: "model",
          parts: [{ text: "Oops, something went wrong. Please try again later." }]
        });
      }
    });
