
document.addEventListener("DOMContentLoaded", function () {
  // ----------------------------
  // File input logic
  // ----------------------------
  const fileInput = document.getElementById("logfile");
  const fileNameDisplay = document.getElementById("file-name");
  const uploadForm = document.querySelector(".upload-form");
  const uploadBtn = document.querySelector(".upload-btn");

  if (fileInput) {
    fileInput.addEventListener("change", function (e) {
      const file = e.target.files[0];
      if (file) {
        if (fileNameDisplay) fileNameDisplay.textContent = file.name;
        if (file.size > 5 * 1024 * 1024) {
          alert("⚠️ File size exceeds 5 MB. Consider smaller file for faster analysis.");
        }
      } else {
        if (fileNameDisplay) fileNameDisplay.textContent = "No file selected";
      }
    });
  }

  // ----------------------------
  // Upload form submission (spinner + validation)
  // ----------------------------
  if (uploadForm && uploadBtn) {
    uploadForm.addEventListener("submit", function (e) {
      const file = fileInput?.files[0];
      if (!file) {
        e.preventDefault();
        alert("⚠️ Please select a file before uploading.");
        return;
      }

      // Add spinner feedback
      uploadBtn.disabled = true;
      const originalHTML = uploadBtn.innerHTML;
      uploadBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Analyzing...`;
    });
  }

  // ----------------------------
  // Sidebar collapse toggle
  // ----------------------------
  const sidebar = document.getElementById("sidebar");
  const toggleBtn = document.getElementById("toggleBtn");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
    });
  }

  // ----------------------------
  // Optional: Sidebar menu item highlight
  // ----------------------------
  const menuItems = document.querySelectorAll(".menu a");
  menuItems.forEach((item) => {
    item.addEventListener("click", () => {
      menuItems.forEach((i) => i.classList.remove("active"));
      item.classList.add("active");
    });
  });
});
