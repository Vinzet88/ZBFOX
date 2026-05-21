<?php
declare(strict_types=1);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.html#contatti');
    exit;
}

function clean_input(string $value): string {
    $value = trim($value);
    $value = str_replace(["\r", "\n"], ' ', $value);
    return $value;
}

$name = clean_input($_POST['Nome'] ?? '');
$email = filter_var(trim($_POST['Email'] ?? ''), FILTER_VALIDATE_EMAIL);
$message = trim($_POST['Messaggio'] ?? '');

if ($name === '' || $email === false || $message === '') {
    header('Location: index.html#contatti');
    exit;
}

$to = 'info@zbfox.it';
$subject = 'Richiesta contatto da sito ZBFOX';
$body = "Nuova richiesta dal sito ZBFOX\n\n"
    . "Nome: {$name}\n"
    . "Email: {$email}\n\n"
    . "Messaggio:\n{$message}\n";

$headers = [
    'From: ZBFOX Website <no-reply@' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '>',
    'Reply-To: ' . $email,
    'Content-Type: text/plain; charset=UTF-8'
];

@mail($to, $subject, $body, implode("\r\n", $headers));

header('Location: index.html#contatti');
exit;
