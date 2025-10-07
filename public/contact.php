<?php
// public/contact.php
// Simple contact form handler using native PHP mail().
// No composer or external libs required. Designed for FTP-only hosting.
// This script returns JSON for AJAX requests, otherwise redirects back with a query string (success or error).

// --- Basic hardening ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo 'Method Not Allowed';
    exit;
}

// Small helper to detect AJAX/JSON requests
function wants_json() {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        return true;
    }
    if (!empty($_SERVER['HTTP_ACCEPT']) && stripos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
        return true;
    }
    return false;
}

function redirect_back(array $params) {
    $referer = $_SERVER['HTTP_REFERER'] ?? '/';
    $sep = (parse_url($referer, PHP_URL_QUERY) === null) ? '?' : '&';
    header('Location: ' . $referer . $sep . http_build_query($params));
    exit;
}

function respond($ok, $message, $extra = []) {
    $payload = array_merge(['success' => (bool)$ok, 'message' => $message], $extra);
    if (wants_json()) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload);
        exit;
    }
    redirect_back($payload);
}

// --- Spam honeypot ---
$honeypot = isset($_POST['website']) ? trim((string)$_POST['website']) : '';
if ($honeypot !== '') {
    // Silently drop or pretend success to avoid giving feedback to bots
    respond(true, 'Message received.');
}

// --- Gather and sanitize input ---
$fields = [
    'name'    => FILTER_SANITIZE_SPECIAL_CHARS,
    'mail'    => FILTER_VALIDATE_EMAIL,
    'phone'   => FILTER_SANITIZE_SPECIAL_CHARS,
    'subject' => FILTER_SANITIZE_SPECIAL_CHARS,
    'message' => FILTER_UNSAFE_RAW,
];
$input = filter_input_array(INPUT_POST, $fields, false) ?: [];

$name = isset($input['name']) ? trim((string)$input['name']) : '';
$email = isset($input['mail']) ? trim((string)$input['mail']) : '';
$phone = isset($input['phone']) ? trim((string)$input['phone']) : '';
$subject = isset($input['subject']) ? trim((string)$input['subject']) : '';
$message = isset($input['message']) ? trim((string)$input['message']) : '';

// Further normalize
$subject = $subject !== '' ? $subject : 'Nuevo mensaje del formulario de contacto';

// Basic validation
$errors = [];
if ($name === '' || mb_strlen($name) > 200) { $errors[] = 'Nombre inválido.'; }
if ($email === false || $email === '' || mb_strlen($email) > 254) { $errors[] = 'Email inválido.'; }
if ($message === '' || mb_strlen($message) > 5000) { $errors[] = 'Mensaje inválido.'; }
if (!empty($errors)) {
    respond(false, implode(' ', $errors));
}

// --- Mail addresses (edit these or set ENV variables) ---
$toEmail      = getenv('CONTACT_TO_EMAIL') ?: 'info@sysmo.com.ar'; // Destino
$toName       = getenv('CONTACT_TO_NAME')  ?: 'Sysmo';
$fromEmail    = getenv('MAIL_FROM_EMAIL') ?: 'no-reply@tu-dominio.com';
$fromName     = getenv('MAIL_FROM_NAME')  ?: 'Formulario de Contacto';
// Algunos hosts requieren envelope sender (-f). Si tu proveedor lo exige, seteá MAIL_ENVELOPE_FROM
$envelopeFrom = getenv('MAIL_ENVELOPE_FROM') ?: '';

// Helpers for fallback mail()
function encode_mime_header($text) {
    return '=?UTF-8?B?' . base64_encode($text) . '?=';
}

try {
    $safeName    = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeEmail   = htmlspecialchars($email, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safePhone   = htmlspecialchars($phone, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeMessage = nl2br(htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));

    $htmlBody = "<h2>Nuevo mensaje de contacto</h2>"
        . "<p><strong>Nombre:</strong> {$safeName}</p>"
        . "<p><strong>Email:</strong> {$safeEmail}</p>"
        . ($safePhone !== '' ? "<p><strong>Teléfono:</strong> {$safePhone}</p>" : '')
        . "<p><strong>Mensaje:</strong><br>{$safeMessage}</p>";

    $altBody = "Nuevo mensaje de contacto\n"
        . "Nombre: {$name}\n"
        . "Email: {$email}\n"
        . ($phone !== '' ? "Teléfono: {$phone}\n" : '')
        . "Mensaje:\n{$message}\n";

    // Native mail()
    $headers = [];
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    $headers[] = 'From: ' . encode_mime_header($fromName) . ' <' . $fromEmail . '>';
    $headers[] = 'Reply-To: ' . encode_mime_header($safeName) . ' <' . $safeEmail . '>';
    $headersStr = implode("\r\n", $headers);

    $toHeader = encode_mime_header($toName) . ' <' . $toEmail . '>';
    $params = '';
    if ($envelopeFrom !== '') {
        // Nota: El quinto parámetro es usado por sendmail en Linux. En Windows se ignora.
        $params = '-f ' . $envelopeFrom;
    }
    $ok = $params !== ''
        ? @mail($toHeader, encode_mime_header($subject), $htmlBody, $headersStr, $params)
        : @mail($toHeader, encode_mime_header($subject), $htmlBody, $headersStr);

    if ($ok) {
        respond(true, 'Tu mensaje fue enviado correctamente. ¡Gracias!');
    } else {
        respond(false, 'No se pudo enviar el mensaje. Verifica la configuración de correo del hosting.');
    }
} catch (Exception $e) {
    respond(false, 'No se pudo enviar el mensaje: ' . $e->getMessage());
}
