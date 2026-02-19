package com.example

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import java.io.File
import java.net.URLEncoder
import java.sql.Connection
import java.sql.DriverManager

data class Book(
    val id: Int,
    val title: String,
    val author: String,
    val year: Int,
    val location: String
)

data class User(
    val username: String,
    val email: String,
    val password: String
)

fun Application.configureRouting() {

    install(Sessions) {
        cookie<String>("user") {
            cookie.path = "/"
            cookie.httpOnly = true
        }
    }

    // ---- SQLite init ----
    val db = SqliteDb("data/library.db")
    db.init()

    // Basket stays in memory (per server run)
    val basketByUser = mutableMapOf<String, MutableSet<Int>>()

    routing {

        get("/") {
            val username = call.sessions.get<String>()
            val status = if (username == null) "Not logged in" else "Logged in as <b>${escapeHtml(username)}</b>"

            call.respondText(
                """
                <html><body>
                  <h1>Library System</h1>
                  <p>Status: $status</p>
                  <ul>
                    <li><a href="/register">Register</a></li>
                    <li><a href="/login">Login</a></li>
                    <li><a href="/books">Books</a> (login required)</li>
                    <li><a href="/logout">Logout</a></li>
                  </ul>
                </body></html>
                """.trimIndent(),
                ContentType.Text.Html
            )
        }

        // ---------------- Register (NO login required) ----------------
        get("/register") {
            val msg = call.request.queryParameters["msg"]?.let { escapeHtml(it) }.orEmpty()
            val messageBox = if (msg.isBlank()) "" else "<p><b>$msg</b></p>"
            val current = call.sessions.get<String>()
            val note = if (current == null) "" else
                "<p><i>Note: You are currently logged in as <b>${escapeHtml(current)}</b>. Registering a new account will log you out.</i></p>"

            call.respondText(
                """
                <html><body>
                  <h1>Register</h1>
                  $messageBox
                  $note
                  <form action="/register" method="post">
                    <p>Username: <input type="text" name="username"/></p>
                    <p>Email: <input type="email" name="email"/></p>
                    <p>Password: <input type="password" name="password"/></p>
                    <button type="submit">Register</button>
                  </form>
                  <p><a href="/">Back to Home</a></p>
                </body></html>
                """.trimIndent(),
                ContentType.Text.Html
            )
        }

        post("/register") {
            val p = call.receiveParameters()
            val username = p["username"]?.trim().orEmpty()
            val email = p["email"]?.trim().orEmpty()
            val password = p["password"]?.trim().orEmpty()

            if (username.isBlank() || email.isBlank() || password.isBlank()) {
                redirectToRegister(call, "All fields are required (username, email, password).")
                return@post
            }

            if (db.userExists(username)) {
                redirectToRegister(call, "Username already exists.")
                return@post
            }

            db.createUser(User(username, email, password))

            // ✅ FIX: If someone registers while logged in, log them out to avoid "account switch confusion"
            val oldUser = call.sessions.get<String>()
            if (oldUser != null) {
                basketByUser.remove(oldUser)
                call.sessions.clear<String>()
            }

            redirectToLogin(call, "Registration successful. Please login.")
        }

        // ---------------- Login ----------------
        get("/login") {
            val msg = call.request.queryParameters["msg"]?.let { escapeHtml(it) }.orEmpty()
            val messageBox = if (msg.isBlank()) "" else "<p><b>$msg</b></p>"

            val current = call.sessions.get<String>()
            val note = if (current == null) "" else
                "<p><i>You are currently logged in as <b>${escapeHtml(current)}</b>. Logging in will switch account.</i></p>"

            call.respondText(
                """
                <html><body>
                  <h1>Login</h1>
                  $messageBox
                  $note
                  <form action="/login" method="post">
                    <p>Username: <input type="text" name="username"/></p>
                    <p>Password: <input type="password" name="password"/></p>
                    <button type="submit">Login</button>
                  </form>
                  <p><a href="/">Back to Home</a></p>
                </body></html>
                """.trimIndent(),
                ContentType.Text.Html
            )
        }

        post("/login") {
            val p = call.receiveParameters()
            val username = p["username"]?.trim().orEmpty()
            val password = p["password"]?.trim().orEmpty()

            if (username.isBlank() || password.isBlank()) {
                call.respondText(
                    "<html><body><h1>Login Failed</h1><p>Please enter username and password.</p><p><a href='/login'>Back</a></p></body></html>",
                    ContentType.Text.Html,
                    HttpStatusCode.BadRequest
                )
                return@post
            }

            val user = db.getUser(username)
            if (user == null || user.password != password) {
                call.respondText(
                    "<html><body><h1>Login Failed</h1><p>Invalid username or password.</p><p><a href='/login'>Back</a></p></body></html>",
                    ContentType.Text.Html,
                    HttpStatusCode.Unauthorized
                )
                return@post
            }

            // Switch account: clear old session basket (optional but keeps behavior clean)
            val oldUser = call.sessions.get<String>()
            if (oldUser != null && oldUser != username) {
                basketByUser.remove(oldUser)
            }

            call.sessions.set<String>(username)
            basketByUser.putIfAbsent(username, mutableSetOf())
            redirectToBooks(call, "Login successful.")
        }

        // Logout
        get("/logout") {
            val username = call.sessions.get<String>()
            if (username != null) basketByUser.remove(username)
            call.sessions.clear<String>()
            call.respondText(
                "<html><body><h1>Logged Out</h1><p><a href='/'>Back to Home</a></p></body></html>",
                ContentType.Text.Html
            )
        }

        // ---------------- Books + Basket (single page) ----------------
        get("/books") {
            val username = requireLoginOrHtml(call) ?: return@get

            val allBooks = loadBooksFromCsv("books.csv")
            val q = call.request.queryParameters["q"]?.trim().orEmpty()
            val filtered = if (q.isBlank()) allBooks else allBooks.filter { it.title.contains(q, ignoreCase = true) }

            val msg = call.request.queryParameters["msg"]?.let { escapeHtml(it) }.orEmpty()
            val messageBox = if (msg.isBlank()) "" else "<p><b>$msg</b></p>"

            val basket = basketByUser.getOrPut(username) { mutableSetOf() }
            val basketBooks = allBooks.filter { basket.contains(it.id) }

            val bookRows = buildString {
                for (b in filtered) {
                    val borrower = db.getBorrower(b.id)
                    val status = when {
                        borrower == null -> "Available"
                        borrower == username -> "Borrowed by you"
                        else -> "Borrowed"
                    }

                    val actionHtml = when {
                        borrower == null && !basket.contains(b.id) -> buttonForm("/basket/add", b.id, "Add to Basket")
                        borrower == null && basket.contains(b.id) -> "<i>In basket</i>"
                        borrower == username -> buttonForm("/books/return", b.id, "Return")
                        else -> "<i>Not available</i>"
                    }

                    append(
                        """
                        <tr>
                          <td>${b.id}</td>
                          <td>${escapeHtml(b.title)}</td>
                          <td>${escapeHtml(b.author)}</td>
                          <td>${b.year}</td>
                          <td>${escapeHtml(b.location)}</td>
                          <td>$status</td>
                          <td>$actionHtml</td>
                        </tr>
                        """.trimIndent()
                    )
                }
            }

            val basketRows = buildString {
                if (basketBooks.isEmpty()) {
                    append("<tr><td colspan='6'><i>Basket is empty.</i></td></tr>")
                } else {
                    for (b in basketBooks) {
                        append(
                            """
                            <tr>
                              <td>${b.id}</td>
                              <td>${escapeHtml(b.title)}</td>
                              <td>${escapeHtml(b.author)}</td>
                              <td>${b.year}</td>
                              <td>${escapeHtml(b.location)}</td>
                              <td>${buttonForm("/basket/remove", b.id, "Remove")}</td>
                            </tr>
                            """.trimIndent()
                        )
                    }
                }
            }

            val checkoutButton = if (basketBooks.isEmpty()) "<button type='submit' disabled>Checkout</button>"
            else "<button type='submit'>Checkout (${basketBooks.size})</button>"

            call.respondText(
                """
                <html><body>
                  <h1>Books</h1>
                  <p>Welcome, <b>${escapeHtml(username)}</b>.</p>
                  $messageBox

                  <form method="get" action="/books">
                    <input name="q" value="${escapeHtml(q)}" placeholder="Search title"/>
                    <button type="submit">Search</button>
                    <a href="/books">Clear</a>
                  </form>

                  <p>Showing ${filtered.size} of ${allBooks.size} books.</p>

                  <table border="1" cellpadding="6" cellspacing="0">
                    <tr>
                      <th>ID</th><th>Title</th><th>Author</th><th>Year</th><th>Location</th><th>Status</th><th>Action</th>
                    </tr>
                    $bookRows
                  </table>

                  <hr/>
                  <h2>Basket</h2>
                  <p>Add multiple books here, then checkout once.</p>

                  <table border="1" cellpadding="6" cellspacing="0">
                    <tr><th>ID</th><th>Title</th><th>Author</th><th>Year</th><th>Location</th><th>Action</th></tr>
                    $basketRows
                  </table>

                  <form action="/basket/checkout" method="post" style="margin-top:10px">
                    $checkoutButton
                    <a href="/basket/clear" style="margin-left:10px">Clear basket</a>
                  </form>

                  <p style="margin-top:20px"><a href="/">Home</a> | <a href="/logout">Logout</a></p>
                </body></html>
                """.trimIndent(),
                ContentType.Text.Html
            )
        }

        // ---------------- Basket actions ----------------
        post("/basket/add") {
            val username = requireLoginOrText(call) ?: return@post
            val id = call.receiveParameters()["id"]?.toIntOrNull()
            if (id == null) {
                redirectToBooks(call, "Invalid book id.")
                return@post
            }

            if (db.getBorrower(id) != null) {
                redirectToBooks(call, "Book is not available.")
                return@post
            }

            basketByUser.getOrPut(username) { mutableSetOf() }.add(id)
            redirectToBooks(call, "Added to basket.")
        }

        post("/basket/remove") {
            val username = requireLoginOrText(call) ?: return@post
            val id = call.receiveParameters()["id"]?.toIntOrNull()
            if (id == null) {
                redirectToBooks(call, "Invalid book id.")
                return@post
            }

            basketByUser.getOrPut(username) { mutableSetOf() }.remove(id)
            redirectToBooks(call, "Removed from basket.")
        }

        get("/basket/clear") {
            val username = requireLoginOrHtml(call) ?: return@get
            basketByUser.getOrPut(username) { mutableSetOf() }.clear()
            redirectToBooks(call, "Basket cleared.")
        }

        post("/basket/checkout") {
            val username = requireLoginOrText(call) ?: return@post

            val books = loadBooksFromCsv("books.csv")
            val basket = basketByUser.getOrPut(username) { mutableSetOf() }
            if (basket.isEmpty()) {
                redirectToBooks(call, "Basket is empty.")
                return@post
            }

            val success = mutableListOf<String>()
            val failed = mutableListOf<String>()

            for (id in basket.toList()) {
                val book = books.find { it.id == id }
                if (book == null) {
                    failed.add("ID $id (not found)")
                    basket.remove(id)
                    continue
                }

                val ok = db.borrowBookIfAvailable(bookId = id, username = username)
                if (!ok) {
                    failed.add("'${book.title}' (already borrowed)")
                    basket.remove(id)
                    continue
                }

                success.add("Borrowed '${book.title}' — Pickup: ${book.location}")
                basket.remove(id)
            }

            val msg = buildString {
                if (success.isNotEmpty()) {
                    append("Checkout successful. ")
                    append(success.joinToString(" | "))
                }
                if (failed.isNotEmpty()) {
                    if (isNotEmpty()) append(" || ")
                    append("Failed: ")
                    append(failed.joinToString(" | "))
                }
            }.ifBlank { "Nothing to checkout." }

            redirectToBooks(call, msg)
        }

        // ---------------- Return (only borrower can return) ----------------
        post("/books/return") {
            val username = requireLoginOrText(call) ?: return@post
            val id = call.receiveParameters()["id"]?.toIntOrNull()
            if (id == null) {
                redirectToBooks(call, "Invalid book id.")
                return@post
            }

            val ok = db.returnBookIfBorrower(bookId = id, username = username)
            if (!ok) {
                redirectToBooks(call, "You can only return books you borrowed.")
                return@post
            }

            redirectToBooks(call, "Returned successfully.")
        }
    }
}

// ---------------- SQLite helper ----------------
private class SqliteDb(private val path: String) {

    fun init() {
        File(path).parentFile?.mkdirs()

        connect().use { c ->
            c.createStatement().use { st ->
                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS users(
                        username TEXT PRIMARY KEY,
                        email    TEXT NOT NULL,
                        password TEXT NOT NULL
                    );
                    """.trimIndent()
                )

                st.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS borrowed(
                        book_id  INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        borrowed_at TEXT NOT NULL DEFAULT (datetime('now')),
                        FOREIGN KEY(username) REFERENCES users(username)
                    );
                    """.trimIndent()
                )
            }
        }
    }

    fun userExists(username: String): Boolean =
        connect().use { c ->
            c.prepareStatement("SELECT 1 FROM users WHERE username = ? LIMIT 1").use { ps ->
                ps.setString(1, username)
                ps.executeQuery().use { rs -> rs.next() }
            }
        }

    fun createUser(user: User) {
        connect().use { c ->
            c.prepareStatement("INSERT INTO users(username,email,password) VALUES(?,?,?)").use { ps ->
                ps.setString(1, user.username)
                ps.setString(2, user.email)
                ps.setString(3, user.password)
                ps.executeUpdate()
            }
        }
    }

    fun getUser(username: String): User? =
        connect().use { c ->
            c.prepareStatement("SELECT username,email,password FROM users WHERE username = ?").use { ps ->
                ps.setString(1, username)
                ps.executeQuery().use { rs ->
                    if (!rs.next()) return null
                    User(
                        username = rs.getString("username"),
                        email = rs.getString("email"),
                        password = rs.getString("password")
                    )
                }
            }
        }

    fun getBorrower(bookId: Int): String? =
        connect().use { c ->
            c.prepareStatement("SELECT username FROM borrowed WHERE book_id = ?").use { ps ->
                ps.setInt(1, bookId)
                ps.executeQuery().use { rs ->
                    if (rs.next()) rs.getString("username") else null
                }
            }
        }

    fun borrowBookIfAvailable(bookId: Int, username: String): Boolean =
        connect().use { c ->
            c.autoCommit = false
            try {
                val already = c.prepareStatement("SELECT 1 FROM borrowed WHERE book_id = ?").use { ps ->
                    ps.setInt(1, bookId)
                    ps.executeQuery().use { rs -> rs.next() }
                }
                if (already) {
                    c.rollback()
                    return false
                }

                c.prepareStatement("INSERT INTO borrowed(book_id, username) VALUES(?, ?)").use { ps ->
                    ps.setInt(1, bookId)
                    ps.setString(2, username)
                    ps.executeUpdate()
                }

                c.commit()
                true
            } catch (_: Exception) {
                c.rollback()
                false
            } finally {
                c.autoCommit = true
            }
        }

    fun returnBookIfBorrower(bookId: Int, username: String): Boolean =
        connect().use { c ->
            c.prepareStatement("DELETE FROM borrowed WHERE book_id = ? AND username = ?").use { ps ->
                ps.setInt(1, bookId)
                ps.setString(2, username)
                ps.executeUpdate() == 1
            }
        }

    private fun connect(): Connection =
        DriverManager.getConnection("jdbc:sqlite:$path")
}

// ---------------- Guards ----------------
private suspend fun requireLoginOrHtml(call: ApplicationCall): String? {
    val username = call.sessions.get<String>()
    if (username == null) {
        call.respondText(
            """
            <html><body>
              <h1>Unauthorized</h1>
              <p>You must <a href="/login">login</a> first.</p>
              <p><a href="/">Back to Home</a></p>
            </body></html>
            """.trimIndent(),
            ContentType.Text.Html,
            HttpStatusCode.Unauthorized
        )
        return null
    }
    return username
}

private suspend fun requireLoginOrText(call: ApplicationCall): String? {
    val username = call.sessions.get<String>()
    if (username == null) {
        call.respondText("Unauthorized", status = HttpStatusCode.Unauthorized)
        return null
    }
    return username
}

// ---------------- Helpers ----------------
private fun buttonForm(action: String, id: Int, label: String): String =
    """
    <form action="$action" method="post" style="margin:0">
      <input type="hidden" name="id" value="$id"/>
      <button type="submit">$label</button>
    </form>
    """.trimIndent()

private suspend fun redirectToBooks(call: ApplicationCall, msg: String) {
    val encoded = URLEncoder.encode(msg, Charsets.UTF_8)
    call.respondText(
        """<html><head><meta http-equiv="refresh" content="0; url=/books?msg=$encoded"></head><body>Redirecting...</body></html>""",
        ContentType.Text.Html
    )
}

private suspend fun redirectToLogin(call: ApplicationCall, msg: String) {
    val encoded = URLEncoder.encode(msg, Charsets.UTF_8)
    call.respondText(
        """<html><head><meta http-equiv="refresh" content="0; url=/login?msg=$encoded"></head><body>Redirecting...</body></html>""",
        ContentType.Text.Html
    )
}

private suspend fun redirectToRegister(call: ApplicationCall, msg: String) {
    val encoded = URLEncoder.encode(msg, Charsets.UTF_8)
    call.respondText(
        """<html><head><meta http-equiv="refresh" content="0; url=/register?msg=$encoded"></head><body>Redirecting...</body></html>""",
        ContentType.Text.Html
    )
}

// CSV loader: id,title,author,year,location
private fun loadBooksFromCsv(resourceName: String): List<Book> {
    val stream = object {}.javaClass.classLoader.getResourceAsStream(resourceName) ?: return emptyList()
    val lines = stream.bufferedReader().readLines()
    if (lines.isEmpty()) return emptyList()

    val dataLines = lines.drop(1).filter { it.isNotBlank() }
    val result = mutableListOf<Book>()

    for (line in dataLines) {
        val parts = line.split(",").map { it.trim() }
        if (parts.size < 4) continue

        val id = parts[0].toIntOrNull() ?: continue
        val title = parts[1]
        val author = parts[2]
        val year = parts[3].toIntOrNull() ?: continue
        val location = if (parts.size >= 5) parts[4] else "Unknown"

        result.add(Book(id, title, author, year, location))
    }

    return result
}

private fun escapeHtml(s: String): String =
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
