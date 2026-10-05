const navContainer = document.getElementById("nav_container");
const navInput = document.getElementById("nav_input");
const hintPill = document.getElementById("hint_pill");

function sendValue(payload) {
  Streamlit.setComponentValue(payload);
}

// Focus on click
navContainer.addEventListener("click", () => {
  navInput.focus();
});

function handlePasteEvent(e) {
  const clipboardData = e.clipboardData || window.clipboardData;
  if (!clipboardData) return;

  const items = clipboardData.items;
  let hasImage = false;

  if (items) {
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.type.indexOf("image") !== -1) {
        hasImage = true;
        e.preventDefault();

        const blob = item.getAsFile();
        const reader = new FileReader();
        reader.onloadend = function () {
          const base64Data = reader.result;
          navInput.innerText = "📷 [Pasted Screenshot / Image Ingress Ready]";
          hintPill.className = "paste-hint-pill success-badge";
          hintPill.innerHTML = "<span>✅ Ingress Active</span>";

          sendValue({
            type: "image",
            data: base64Data,
            ts: Date.now()
          });
        };
        reader.readAsDataURL(blob);
        break;
      }
    }
  }

  // If not a binary image, check for text (URL, file path, or prompt)
  if (!hasImage) {
    const pastedText = clipboardData.getData("text");
    if (pastedText && pastedText.trim().length > 0) {
      setTimeout(() => {
        const text = navInput.innerText.trim();
        sendValue({
          type: "text",
          data: text,
          ts: Date.now()
        });
      }, 50);
    }
  }
}

// Listen on input element
navInput.addEventListener("paste", handlePasteEvent);

// Also listen on window level in case the frame is focused
window.addEventListener("paste", handlePasteEvent);

// Handle Enter keypress for prompt / path input
navInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    const text = navInput.innerText.trim();
    if (text) {
      sendValue({
        type: "text",
        data: text,
        ts: Date.now()
      });
    }
  }
});

// Click hint pill helper
hintPill.addEventListener("click", async (e) => {
  e.stopPropagation();
  try {
    if (navigator.clipboard && navigator.clipboard.read) {
      const clipboardItems = await navigator.clipboard.read();
      for (const clipboardItem of clipboardItems) {
        for (const type of clipboardItem.types) {
          if (type.startsWith("image/")) {
            const blob = await clipboardItem.getType(type);
            const reader = new FileReader();
            reader.onloadend = function () {
              navInput.innerText = "📷 [Pasted Screenshot / Image Ingress Ready]";
              hintPill.className = "paste-hint-pill success-badge";
              hintPill.innerHTML = "<span>✅ Ingress Active</span>";
              sendValue({
                type: "image",
                data: reader.result,
                ts: Date.now()
              });
            };
            reader.readAsDataURL(blob);
            return;
          }
        }
      }
    }
  } catch (err) {
    console.log("Clipboard API read permission check:", err);
  }
  navInput.focus();
});

let isRendered = false;
function onRender(event) {
  if (!isRendered) {
    const args = event.detail.args || {};
    if (args.placeholder) {
      navInput.setAttribute("data-placeholder", args.placeholder);
    }
    Streamlit.setFrameHeight(56);
    isRendered = true;
  }
}

Streamlit.events.addEventListener(Streamlit.RENDER_EVENT, onRender);
Streamlit.setComponentReady();
Streamlit.setFrameHeight(56);
