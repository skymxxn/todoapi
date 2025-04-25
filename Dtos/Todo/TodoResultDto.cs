using System.Diagnostics.CodeAnalysis;

namespace Todo.Api.Dtos.Todo;

public class TodoResultDto<T>
{
    [MemberNotNullWhen(true, nameof(Data))]
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public T? Data { get; set; }
    
    public static TodoResultDto<T> Ok(T? data) => new() { Success = true, Data = data };
    public static TodoResultDto<T> Fail(string error) => new() { Success = false, ErrorMessage = error };
    
}