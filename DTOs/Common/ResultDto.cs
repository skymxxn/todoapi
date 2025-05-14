using System.Diagnostics.CodeAnalysis;

namespace Todo.Api.Dtos.Common;

public class ResultDto<T>
{
    [MemberNotNullWhen(true, nameof(Data))]
    public string? Status { get; set; }
    public string? Message { get; set; }
    public T? Data { get; set; }
    public int StatusCode { get; set; }
    
    public static ResultDto<T> Ok(string message = "Everything is ok", int statusCode = 200) => new()
    {
        Status = "Ok",
        Message = message,
        StatusCode = statusCode
    };
    
    public static ResultDto<T> Ok(T? data, string message = "Everything is ok", int statusCode = 200) => new()
    {
        Status = "Ok",
        Data = data,
        Message = message,
        StatusCode = statusCode
    };
    public static ResultDto<T> Fail(string error = "Something went wrong", int statusCode = 400) => new()
    {
        Status = "Fail",
        Message = error,
        StatusCode = statusCode
    };
    
}