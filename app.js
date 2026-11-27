
"use strict";

const $ = id => document.getElementById(id);

let mode = "login";
let token = localStorage.getItem("scrool_token") || "";
let currentUser = null;
let selectedAvatar = null;

function message(text) {
  if ($("authMessage")) $("authMessage").textContent = text || "";
}

function profileMessage(text, error = false) {
  const el = $("profileMessage");
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("error", error);
}

function setMode(value) {
  mode = value;
  const register = value === "register";

  $("loginTab").classList.toggle("active", !register);
  $("registerTab").classList.toggle("active", register);
  $("authTitle").textContent = register ? "ساخت حساب جدید" : "ورود به حساب";
  $("authSubmit").textContent = register ? "ثبت‌نام" : "ورود";
  $("displayNameBox").classList.toggle("hidden", !register);
  message("");
}

$("loginTab").onclick = () => setMode("login");
$("registerTab").onclick = () => setMode("register");

async function api(url, options = {}) {
  const headers = {
    ...(options.headers || {})
  };

  if (token) headers.Authorization = "Bearer " + token;

  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !headers["Content-Type"]
  ) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch("/api" + url, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "خطایی رخ داد");
  }

  return data;
}

// ورود و ثبت‌نام
$("authForm").onsubmit = async event => {
  event.preventDefault();

  const username = $("username").value.trim();
  const password = $("password").value;

  const body = { username, password };

  if (mode === "register") {
    body.displayName = $("displayName").value.trim();
  }

  try {
    $("authSubmit").disabled = true;
    message("لطفاً صبر کن...");

    const result = await api(
      mode === "register" ? "/register" : "/login",
      {
        method: "POST",
        body: JSON.stringify(body)
      }
    );

    token = result.token;
    localStorage.setItem("scrool_token", token);

    await loadUser();
    showApp();

  } catch (error) {
    message(error.message);
  } finally {
    $("authSubmit").disabled = false;
  }
};

// نمایش اطلاعات کاربر
async function loadUser() {
  const result = await api("/me");
  currentUser = result.user;

  $("profileName").textContent = currentUser.display_name || "";
  $("profileUsername").textContent = "@" + currentUser.username;
  $("profileBio").textContent = currentUser.bio || "";

  $("profileCreated").textContent = currentUser.created_at
    ? "عضویت: " + new Date(currentUser.created_at).toLocaleDateString("fa-IR")
    : "";

  if ($("editDisplayName")) {
    $("editDisplayName").value = currentUser.display_name || "";
  }

  if ($("editBio")) {
    $("editBio").value = currentUser.bio || "";
  }

  selectedAvatar = currentUser.avatar || null;
  showAvatar(selectedAvatar);

  if ($("profilePostCount")) {
    $("profilePostCount").textContent =
      currentUser.post_count ?? "۰";
  }

  if ($("profileFollowers")) {
    $("profileFollowers").textContent =
      currentUser.followers_count ?? "۰";
  }

  if ($("profileFollowing")) {
    $("profileFollowing").textContent =
      currentUser.following_count ?? "۰";
  }
}

// نمایش عکس پروفایل
function showAvatar(src) {
  const image = $("profileAvatar");
  const placeholder = $("avatarPlaceholder");

  if (!image || !placeholder) return;

  if (src) {
    image.src = src;
    image.classList.remove("hidden");
    placeholder.classList.add("hidden");
  } else {
    image.removeAttribute("src");
    image.classList.add("hidden");
    placeholder.classList.remove("hidden");
  }
}

// فشرده‌سازی عکس پروفایل
function compressImage(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onload = () => {
      const img = new Image();

      img.onload = () => {
        const maxSize = 400;
        const scale = Math.min(
          1,
          maxSize / Math.max(img.width, img.height)
        );

        const canvas = document.createElement("canvas");
        canvas.width = Math.round(img.width * scale);
        canvas.height = Math.round(img.height * scale);

        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

        resolve(canvas.toDataURL("image/jpeg", 0.78));
      };

      img.onerror = () => reject(new Error("خواندن عکس ناموفق بود."));
      img.src = reader.result;
    };

    reader.onerror = () => reject(new Error("خطا در انتخاب عکس."));
    reader.readAsDataURL(file);
  });
}

// انتخاب عکس پروفایل
if ($("avatarInput")) {
  $("avatarInput").addEventListener("change", async event => {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      profileMessage("لطفاً یک فایل تصویری انتخاب کن.", true);
      return;
    }

    if (file.size > 8 * 1024 * 1024) {
      profileMessage("حجم عکس نباید بیشتر از ۸ مگابایت باشد.", true);
      event.target.value = "";
      return;
    }

    try {
      profileMessage("در حال آماده‌سازی عکس...");
      selectedAvatar = await compressImage(file);
      showAvatar(selectedAvatar);
      profileMessage("عکس انتخاب شد؛ برای ذخیره، دکمه ثبت تغییرات را بزن.");
    } catch (error) {
      profileMessage(error.message, true);
    }
  });
}

// ذخیره پروفایل
if ($("editProfileForm")) {
  $("editProfileForm").addEventListener("submit", async event => {
    event.preventDefault();

    const displayName = $("editDisplayName").value.trim();
    const bio = $("editBio").value.trim();

    if (displayName.length < 2 || displayName.length > 60) {
      profileMessage("نام نمایشی باید بین ۲ تا ۶۰ حرف باشد.", true);
      return;
    }

    try {
      $("saveProfileBtn").disabled = true;
      profileMessage("در حال ذخیره تغییرات...");

      await api("/profile", {
        method: "PUT",
        body: JSON.stringify({
          displayName,
          bio,
          avatar: selectedAvatar
        })
      });

      await loadUser();
      profileMessage("تغییرات پروفایل با موفقیت ذخیره شد.");

    } catch (error) {
      profileMessage(error.message, true);
    } finally {
      $("saveProfileBtn").disabled = false;
    }
  });
}

// نمایش صفحات
function showApp() {
  $("authPage").classList.add("hidden");
  $("appPage").classList.remove("hidden");
}

function showAuth() {
  $("appPage").classList.add("hidden");
  $("authPage").classList.remove("hidden");
}

// خروج
$("logoutBtn").onclick = () => {
  token = "";
  currentUser = null;
  selectedAvatar = null;
  localStorage.removeItem("scrool_token");
  showAuth();
};

// تغییر تم
$("themeToggle").onclick = () => {
  document.body.classList.toggle("light");

  localStorage.setItem(
    "scrool_theme",
    document.body.classList.contains("light") ? "light" : "dark"
  );
};

if (localStorage.getItem("scrool_theme") === "light") {
  document.body.classList.add("light");
}

// منوی صفحات
document.querySelectorAll(".nav-btn").forEach(button => {
  button.onclick = () => {
    const page = button.dataset.page;

    document.querySelectorAll(".nav-btn").forEach(item => {
      item.classList.remove("active");
    });

    button.classList.add("active");

    ["home", "profile", "messages", "notifications"].forEach(name => {
      const pageElement = $(name + "Page");
      if (pageElement) {
        pageElement.classList.toggle("hidden", name !== page);
      }
    });

    if (page === "profile" && token) {
      loadUser().catch(error => profileMessage(error.message, true));
    }
  };
});

// انتشار پست؛ در مرحله بعد به آپلود چندرسانه‌ای وصل می‌شود
if ($("publishPost")) {
  $("publishPost").onclick = () => {
    alert("بخش انتشار پست در مرحله بعد فعال می‌شود.");
  };
}

// استوری
if ($("addStoryBtn")) {
  $("addStoryBtn").onclick = () => {
    $("storyModal").classList.remove("hidden");
  };
}

if ($("closeStory")) {
  $("closeStory").onclick = () => {
    $("storyModal").classList.add("hidden");
  };
}

if ($("submitStory")) {
  $("submitStory").onclick = () => {
    $("storyMessage").textContent =
      "بخش استوری در مرحله بعد به سرور متصل می‌شود.";
  };
}

// شروع برنامه
async function init() {
  if (!token) return;

  try {
    await loadUser();
    showApp();
  } catch {
    token = "";
    localStorage.removeItem("scrool_token");
    showAuth();
  }
}

init();
