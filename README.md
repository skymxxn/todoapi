# Todo API

Это полнофункциональное веб-приложение (REST API), написанное на ASP.NET Core, предназначенное для управления задачами (todo items). В нём реализованы регистрация пользователей, подтверждение email, JWT-аутентификация, работа с задачами и категориями, просмотр/редактирование профиля (username, email, password), логирование и ограничение запросов.

## :pushpin: Функциональность

- :lock: JWT + refresh токены  
- :email: Подтверждение email и восстановление пароля  
- :white_check_mark: CRUD-операции для задач и категорий  
- :mag: Фильтрация, сортировка и пагинация задач
- :bust_in_silhouette: Просмтр, редактирование профиля
- :zap: Кэширование In-Memory
- :repeat: Middleware для логирования, обработки ошибок и лимитирования запросов  
- :gear: Разделение на слои: Entities, DTOs, Services, Controllers  
- :bar_chart: Подключение Serilog и ExpressionTemplate для логов  
- :construction: Валидация данных с помощью FluentValidation  

## :gear: Технологии

- ASP.NET Core 9  
- Entity Framework Core + PostgreSQL
- In-Memory Cache  
- JWT (Json Web Token)  
- Serilog + Seq  
- FluentValidation  
- Rate limiting  

## :rocket: Быстрый старт

### 1. Клонировать проект

```bash
git clone https://github.com/skymxxn/todoapi.git
```

### 2. Настроить переменные окружения

Создайте файл `appsettings.Development.json` с вашими ключами:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Username=YOUR_DB_USERNAME;Password=YOUR_DB_PASSWORD;Database=TodoDb;"
  },
  "AppSettings": {
    "AccessTokenKey": "YOUR_ACCESS_TOKEN_KEY",
    "AccessTokenExpirationInMinutes": "15",
    "EmailVerificationTokenKey": "YOUR_EMAIL_VERIFICATION_KEY",
    "EmailVerificationTokenExpirationInMinutes": "60",
    "EmailChangeTokenKey": "YOUR_EMAIL_CHANGE_KEY",
    "EmailChangeTokenExpirationInMinutes": "60",
    "PasswordResetTokenKey": "YOUR_PASSWORD_RESET_KEY",
    "PasswordResetTokenExpirationInMinutes": "60",
    "Issuer": "YOUR_ISSUER",
    "Audience": "YOUR_AUDIENCE"
  },
  "Frontend": {
    "BaseUrl": "http://localhost:5173",
    "VerificationUrl": "http://localhost:5173/auth/confirm-email?token={0}",
    "ChangeEmailUrl": "http://localhost:5173/account/confirm-email-change?token={0}",
    "ResetPasswordUrl": "http://localhost:5173/auth/reset-password?token={0}"
  },
  "Smtp": {
    "Host": "smtp.example.com",
    "Port": 587,
    "Email": "your@email.com",
    "Password": "your-email-password"
  },
  "Cors": {
    "AllowedOrigins": [
      "http://localhost:5173"
    ]
  }
}
```

### 3. Создание и применение миграции

#### Создайте начальную миграцию

```bash
dotnet ef migrations add InitialCreate
```

#### Примените миграцию к базе данных

```bash
dotnet ef database update
```

### 4. Запуск проекта

```bash
dotnet run
```

После запуска API будет доступно по адресу: [http://localhost:{port}](http://localhost:{port})

### 5. Документация API

Проект использует **Scalar**.  
Для доступа к документации перейдите по адресу: [http://localhost:{port}/scalar](http://localhost:{port}/scalar)

## :paperclip: Структура проекта

```
TodoApi/
├── Controllers/          # Контроллеры API
├── Services/             # Бизнес-логика
├── DTOs/                 # Модели для входящих/исходящих данных
├── Entities/             # Модели базы данных
├── Enums/                # Enum-значения (например, Role, Status и т.п.)
├── Configurations/       # Конфигурации EF Core
├── Middlewares/          # Middleware-компоненты
├── Extensions/           # Расширения сервисов и builder’ов
```

## :bust_in_silhouette: Автор

Разработано с нуля.  
Автор: **Руслан** ([@skymxxn](https://github.com/skymxxn))

## :mailbox: Контакты

Если есть желание пообщаться, дать фидбек или предложить сотрудничество — пишите в [Telegram](https://t.me/skymxxn) или на [GitHub](https://github.com/skymxxn)
