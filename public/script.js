function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let products = [];
let isAdmin = false;
const cart = [];
let receiptCounter = 1;
let authToken = sessionStorage.getItem("token") || "";

function setMessage(id, text) {
  document.getElementById(id).textContent = text;
}

/* ---------- Products ---------- */

async function loadProducts() {
  try {
    const response = await fetch("/api/products");
    products = await response.json();
    displayProducts();
  } catch (error) {
    document.getElementById("productList").innerHTML = "<p>Could not load products.</p>";
  }
}

function displayProducts() {
  const list = document.getElementById("productList");
  const searchBox = document.getElementById("searchBox");
  const search = searchBox ? searchBox.value.toLowerCase().trim() : "";
  list.innerHTML = "";

  let found = false;

  for (let i = 0; i < products.length; i++) {
    const product = products[i];

    if (product.name.toLowerCase().includes(search)) {
      found = true;

      let deleteBtn = "";
      if (isAdmin) {
        deleteBtn = " <button onclick='removeProduct(" + product.id + ")'>Delete</button>";
      }

      list.innerHTML +=
        "<p>" + escapeHtml(product.name) + " - GH₵" + product.price +
        " <button onclick='addToCart(" + product.id + ")'>Add to cart</button>" +
        deleteBtn + "</p>";
    }
  }

  if (!found) {
    list.innerHTML = "<p>No products found.</p>";
  }
}

/* ---------- Cart ---------- */

function addToCart(productId) {
  for (let i = 0; i < cart.length; i++) {
    if (cart[i].id === productId) {
      cart[i].qty = cart[i].qty + 1;
      displayCart();
      return;
    }
  }

  for (let i = 0; i < products.length; i++) {
    if (products[i].id === productId) {
      cart.push({
        id: products[i].id,
        name: products[i].name,
        price: products[i].price,
        qty: 1
      });
    }
  }
  displayCart();
}

function calculateTotal() {
  let total = 0;
  for (let i = 0; i < cart.length; i++) {
    total = total + cart[i].price * cart[i].qty;
  }
  return total;
}

function getItemCount() {
  let count = 0;
  for (let i = 0; i < cart.length; i++) {
    count = count + cart[i].qty;
  }
  return count;
}

function getDiscount(total) {
  if (total >= 200) {
    return 0.10;
  } else if (total >= 100) {
    return 0.05;
  } else {
    return 0;
  }
}

function displaySummary() {
  const total = calculateTotal();
  const discountRate = getDiscount(total);
  const discountAmount = total * discountRate;
  const finalTotal = total - discountAmount;

  let html =
    "Subtotal: GH₵" + total.toFixed(2) + "<br>" +
    "Discount: GH₵" + discountAmount.toFixed(2) + "<br>" +
    "<strong>Total to pay: GH₵" + finalTotal.toFixed(2) + "</strong>";

  if (discountAmount > 0) {
    html += "<br>You saved GH₵" + discountAmount.toFixed(2) + "!";
  }

  if (total > 0 && total < 100) {
    html += "<br>Add GH₵" + (100 - total).toFixed(2) + " more to get 5% off.";
  } else if (total >= 100 && total < 200) {
    html += "<br>Add GH₵" + (200 - total).toFixed(2) + " more to get 10% off.";
  }

  document.getElementById("summary").innerHTML = html;
}

function displayCart() {
  const list = document.getElementById("cartList");
  list.innerHTML = "";

  const count = getItemCount();
  document.getElementById("cartHeading").textContent =
    "Your Cart (" + count + (count === 1 ? " item)" : " items)");

  if (cart.length === 0) {
    list.innerHTML = "<p>Your cart is empty.</p>";
    displaySummary();
    return;
  }

  for (let i = 0; i < cart.length; i++) {
    const lineTotal = cart[i].price * cart[i].qty;
    list.innerHTML +=
      "<p>" + escapeHtml(cart[i].name) + " - GH₵" + lineTotal +
      " <span>" +
      "<button onclick='decreaseQty(" + i + ")'>-</button> " +
      cart[i].qty + " " +
      "<button onclick='increaseQty(" + i + ")'>+</button> " +
      "<button onclick='removeFromCart(" + i + ")'>Remove</button>" +
      "</span></p>";
  }

  displaySummary();
}

function increaseQty(index) {
  cart[index].qty = cart[index].qty + 1;
  displayCart();
}

function decreaseQty(index) {
  cart[index].qty = cart[index].qty - 1;
  if (cart[index].qty === 0) {
    cart.splice(index, 1);
  }
  displayCart();
}

function removeFromCart(index) {
  cart.splice(index, 1);
  displayCart();
}

function clearCart() {
  cart.length = 0;
  displayCart();
}

function checkout() {
  if (cart.length === 0) {
    alert("Your cart is empty.");
    return;
  }

  const total = calculateTotal();
  const discountAmount = total * getDiscount(total);
  const finalTotal = total - discountAmount;
  const now = new Date();

  let html = "<h2>Receipt #" + receiptCounter + "</h2>";
  html += "<p>Date: " + now.toLocaleString() + "</p><hr>";

  for (let i = 0; i < cart.length; i++) {
    const lineTotal = cart[i].price * cart[i].qty;
    html += "<p>" + escapeHtml(cart[i].name) + " x" + cart[i].qty +
            " - GH₵" + lineTotal.toFixed(2) + "</p>";
  }

  html += "<hr>";
  html += "<p>Subtotal: GH₵" + total.toFixed(2) + "</p>";
  html += "<p>Discount: GH₵" + discountAmount.toFixed(2) + "</p>";
  html += "<p><strong>Total paid: GH₵" + finalTotal.toFixed(2) + "</strong></p>";
  html += "<p>Thank you for shopping with us!</p>";
  html += "<button onclick='window.print()'>Print receipt</button>";

  document.getElementById("receipt").innerHTML = html;

  receiptCounter++;
  cart.length = 0;
  displayCart();
}

/* ---------- Account, login and MFA ---------- */

async function register() {
  const username = document.getElementById("authUser").value;
  const password = document.getElementById("authPass").value;

  const response = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, password: password })
  });
  const data = await response.json();
  setMessage("authMsg", data.error || data.message);
}

async function login() {
  const username = document.getElementById("authUser").value;
  const password = document.getElementById("authPass").value;
  const codeBox = document.getElementById("authCode");
  const code = codeBox.hidden ? "" : codeBox.value;

  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, password: password, code: code })
  });
  const data = await response.json();

  if (data.mfaRequired) {
    codeBox.hidden = false;
    codeBox.focus();
    setMessage("authMsg", "Enter the 6-digit code from your authenticator app, then click Log in.");
    return;
  }

  if (data.token) {
    authToken = data.token;
    sessionStorage.setItem("token", authToken);
    document.getElementById("authPass").value = "";
    codeBox.value = "";
    codeBox.hidden = true;
    setMessage("authMsg", "");
    showAccount();
  } else {
    setMessage("authMsg", data.error);
  }
}

function logout() {
  authToken = "";
  sessionStorage.removeItem("token");
  isAdmin = false;
  document.getElementById("loggedOut").hidden = false;
  document.getElementById("loggedIn").hidden = true;
  document.getElementById("adminBox").hidden = true;
  document.getElementById("mfaBox").hidden = true;
  displayProducts();
}

async function showAccount() {
  if (authToken === "") {
    return;
  }

  const response = await fetch("/api/me", {
    headers: { Authorization: "Bearer " + authToken }
  });

  if (!response.ok) {
    logout();
    return;
  }

  const me = await response.json();
  document.getElementById("loggedOut").hidden = true;
  document.getElementById("loggedIn").hidden = false;
  document.getElementById("welcome").textContent =
    "Logged in as " + me.username + " (" + me.role + ") ";

  const adminReady = me.role === "admin" && me.mfaEnabled;
  document.getElementById("adminBox").hidden = !adminReady;
  isAdmin = adminReady;
  displayProducts();

  if (me.role === "admin" && !me.mfaEnabled) {
    setMessage("authMsg", "Admin accounts must enable MFA. Click Enable MFA, scan the QR code, then confirm.");
  }
}

async function startMfa() {
  const response = await fetch("/api/mfa/setup", {
    method: "POST",
    headers: { Authorization: "Bearer " + authToken }
  });
  const data = await response.json();

  if (!response.ok) {
    setMessage("authMsg", data.error);
    return;
  }

  document.getElementById("mfaQr").src = data.qr;
  document.getElementById("mfaSecret").textContent = data.secret;
  document.getElementById("mfaBox").hidden = false;
}

async function confirmMfa() {
  const code = document.getElementById("mfaCode").value;

  const response = await fetch("/api/mfa/enable", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + authToken
    },
    body: JSON.stringify({ code: code })
  });
  const data = await response.json();

  setMessage("authMsg", data.error || data.message);
  if (response.ok) {
    document.getElementById("mfaBox").hidden = true;
    document.getElementById("mfaCode").value = "";
    showAccount();
  }
}

/* ---------- Admin ---------- */

async function addProduct() {
  const name = document.getElementById("newName").value;
  const price = Number(document.getElementById("newPrice").value);

  const response = await fetch("/api/products", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + authToken
    },
    body: JSON.stringify({ name: name, price: price })
  });
  const data = await response.json();

  if (response.ok) {
    setMessage("adminMsg", "Added " + data.name);
    loadProducts();
  } else {
    setMessage("adminMsg", data.error);
  }
}

async function removeProduct(id) {
  if (!confirm("Delete this product?")) {
    return;
  }

  const response = await fetch("/api/products/" + id, {
    method: "DELETE",
    headers: { Authorization: "Bearer " + authToken }
  });
  const data = await response.json();

  setMessage("adminMsg", data.error || data.message);
  if (response.ok) {
    loadProducts();
  }
}

/* ---------- Start up ---------- */

loadProducts();
displayCart();
showAccount();