const form = document.getElementById("uploadForm");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorBox.classList.add("hidden");
    loading.classList.remove("hidden");

    const fd = new FormData(form);
    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: fd
      });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(msg || "업로드 실패");
      }
      const data = await res.json();
      // 결과 페이지로 이동
      window.location.href = data.result_url;
    } catch (err) {
      loading.classList.add("hidden");
      errorBox.textContent = err.message || String(err);
      errorBox.classList.remove("hidden");
    }
  });
}

