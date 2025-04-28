using System.Diagnostics.CodeAnalysis;

namespace Todo.Api.Dtos.Todo;

public class TodoResultDto<T>
{
    [MemberNotNullWhen(true, nameof(Data))]
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public T? Data { get; set; }
    public int StatusCode { get; set; }
    
    public static TodoResultDto<T> Ok(T? data, int statusCode = 200) => new()
    {
        Success = true,
        Data = data,
        StatusCode = statusCode
    };
    public static TodoResultDto<T> Fail(string error, int statusCode = 400) => new()
    {
        Success = false,
        ErrorMessage = error,
        StatusCode = statusCode
    };
    
}