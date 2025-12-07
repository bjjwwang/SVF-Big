; ModuleID = 'llvm-link'
source_filename = "llvm-link"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-unknown-linux-gnu"

%struct.error = type { ptr, i64 }
%struct.internal_hooks = type { ptr, ptr, ptr }
%struct.cJSON = type { ptr, ptr, ptr, i32, ptr, i32, double, ptr }
%struct.cJSON_Hooks = type { ptr, ptr }
%struct.parse_buffer = type { ptr, i64, i64, i64, %struct.internal_hooks }
%struct.printbuffer = type { ptr, i64, i64, i64, i32, i32, %struct.internal_hooks }

@global_error = internal global %struct.error zeroinitializer, align 8
@cJSON_Version.version = internal global [15 x i8] zeroinitializer, align 1
@.str = private unnamed_addr constant [9 x i8] c"%i.%i.%i\00", align 1
@global_hooks = internal global %struct.internal_hooks { ptr @malloc, ptr @free, ptr @realloc }, align 8
@.str.1 = private unnamed_addr constant [4 x i8] c"\EF\BB\BF\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"null\00", align 1
@.str.3 = private unnamed_addr constant [6 x i8] c"false\00", align 1
@.str.4 = private unnamed_addr constant [5 x i8] c"true\00", align 1
@.str.5 = private unnamed_addr constant [3 x i8] c"%d\00", align 1
@.str.6 = private unnamed_addr constant [7 x i8] c"%1.15g\00", align 1
@.str.7 = private unnamed_addr constant [4 x i8] c"%lg\00", align 1
@.str.8 = private unnamed_addr constant [7 x i8] c"%1.17g\00", align 1
@.str.9 = private unnamed_addr constant [3 x i8] c"\22\22\00", align 1
@.str.10 = private unnamed_addr constant [6 x i8] c"u%04x\00", align 1
@.str.11 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@.str.1.12 = private unnamed_addr constant [7 x i8] c"/%lu%s\00", align 1
@.str.2.14 = private unnamed_addr constant [5 x i8] c"path\00", align 1
@.str.3.16 = private unnamed_addr constant [6 x i8] c"value\00", align 1
@apply_patch.invalid = internal constant %struct.cJSON zeroinitializer, align 8
@.str.4.17 = private unnamed_addr constant [5 x i8] c"from\00", align 1
@.str.5.18 = private unnamed_addr constant [2 x i8] c"-\00", align 1
@.str.6.20 = private unnamed_addr constant [3 x i8] c"op\00", align 1
@.str.7.21 = private unnamed_addr constant [4 x i8] c"add\00", align 1
@.str.8.22 = private unnamed_addr constant [7 x i8] c"remove\00", align 1
@.str.9.23 = private unnamed_addr constant [8 x i8] c"replace\00", align 1
@.str.10.24 = private unnamed_addr constant [5 x i8] c"move\00", align 1
@.str.11.25 = private unnamed_addr constant [5 x i8] c"copy\00", align 1
@.str.12 = private unnamed_addr constant [5 x i8] c"test\00", align 1
@.str.13 = private unnamed_addr constant [4 x i8] c"%s/\00", align 1
@.str.14 = private unnamed_addr constant [7 x i8] c"%s/%lu\00", align 1
@.str.15 = private unnamed_addr constant [4 x i8] c"%lu\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_GetErrorPtr() #0 {
  %1 = load ptr, ptr @global_error, align 8
  %2 = load i64, ptr getelementptr inbounds (%struct.error, ptr @global_error, i32 0, i32 1), align 8
  %3 = getelementptr inbounds i8, ptr %1, i64 %2
  ret ptr %3
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_GetStringValue(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = call i32 @cJSON_IsString(ptr noundef %4)
  %6 = icmp ne i32 %5, 0
  br i1 %6, label %8, label %7

7:                                                ; preds = %1
  store ptr null, ptr %2, align 8
  br label %12

8:                                                ; preds = %1
  %9 = load ptr, ptr %3, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 4
  %11 = load ptr, ptr %10, align 8
  store ptr %11, ptr %2, align 8
  br label %12

12:                                               ; preds = %8, %7
  %13 = load ptr, ptr %2, align 8
  ret ptr %13
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsString(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 16
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local double @cJSON_GetNumberValue(ptr noundef %0) #0 {
  %2 = alloca double, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = call i32 @cJSON_IsNumber(ptr noundef %4)
  %6 = icmp ne i32 %5, 0
  br i1 %6, label %8, label %7

7:                                                ; preds = %1
  store double 0x7FF8000000000000, ptr %2, align 8
  br label %12

8:                                                ; preds = %1
  %9 = load ptr, ptr %3, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 6
  %11 = load double, ptr %10, align 8
  store double %11, ptr %2, align 8
  br label %12

12:                                               ; preds = %8, %7
  %13 = load double, ptr %2, align 8
  ret double %13
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsNumber(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 8
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_Version() #0 {
  %1 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef @cJSON_Version.version, ptr noundef @.str, i32 noundef 1, i32 noundef 7, i32 noundef 19) #8
  ret ptr @cJSON_Version.version
}

; Function Attrs: nounwind
declare i32 @sprintf(ptr noundef, ptr noundef, ...) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_InitHooks(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = icmp eq ptr %3, null
  br i1 %4, label %5, label %6

5:                                                ; preds = %1
  store ptr @malloc, ptr @global_hooks, align 8
  store ptr @free, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  store ptr @realloc, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 2), align 8
  br label %31

6:                                                ; preds = %1
  store ptr @malloc, ptr @global_hooks, align 8
  %7 = load ptr, ptr %2, align 8
  %8 = getelementptr inbounds %struct.cJSON_Hooks, ptr %7, i32 0, i32 0
  %9 = load ptr, ptr %8, align 8
  %10 = icmp ne ptr %9, null
  br i1 %10, label %11, label %15

11:                                               ; preds = %6
  %12 = load ptr, ptr %2, align 8
  %13 = getelementptr inbounds %struct.cJSON_Hooks, ptr %12, i32 0, i32 0
  %14 = load ptr, ptr %13, align 8
  store ptr %14, ptr @global_hooks, align 8
  br label %15

15:                                               ; preds = %11, %6
  store ptr @free, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %16 = load ptr, ptr %2, align 8
  %17 = getelementptr inbounds %struct.cJSON_Hooks, ptr %16, i32 0, i32 1
  %18 = load ptr, ptr %17, align 8
  %19 = icmp ne ptr %18, null
  br i1 %19, label %20, label %24

20:                                               ; preds = %15
  %21 = load ptr, ptr %2, align 8
  %22 = getelementptr inbounds %struct.cJSON_Hooks, ptr %21, i32 0, i32 1
  %23 = load ptr, ptr %22, align 8
  store ptr %23, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  br label %24

24:                                               ; preds = %20, %15
  store ptr null, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 2), align 8
  %25 = load ptr, ptr @global_hooks, align 8
  %26 = icmp eq ptr %25, @malloc
  br i1 %26, label %27, label %31

27:                                               ; preds = %24
  %28 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %29 = icmp eq ptr %28, @free
  br i1 %29, label %30, label %31

30:                                               ; preds = %27
  store ptr @realloc, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 2), align 8
  br label %31

31:                                               ; preds = %30, %27, %24, %5
  ret void
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

; Function Attrs: nounwind
declare void @free(ptr noundef) #1

; Function Attrs: nounwind allocsize(1)
declare ptr @realloc(ptr noundef, i64 noundef) #3

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_Delete(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  store ptr null, ptr %3, align 8
  br label %4

4:                                                ; preds = %61, %1
  %5 = load ptr, ptr %2, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %65

7:                                                ; preds = %4
  %8 = load ptr, ptr %2, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 0
  %10 = load ptr, ptr %9, align 8
  store ptr %10, ptr %3, align 8
  %11 = load ptr, ptr %2, align 8
  %12 = getelementptr inbounds %struct.cJSON, ptr %11, i32 0, i32 3
  %13 = load i32, ptr %12, align 8
  %14 = and i32 %13, 256
  %15 = icmp ne i32 %14, 0
  br i1 %15, label %25, label %16

16:                                               ; preds = %7
  %17 = load ptr, ptr %2, align 8
  %18 = getelementptr inbounds %struct.cJSON, ptr %17, i32 0, i32 2
  %19 = load ptr, ptr %18, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %25

21:                                               ; preds = %16
  %22 = load ptr, ptr %2, align 8
  %23 = getelementptr inbounds %struct.cJSON, ptr %22, i32 0, i32 2
  %24 = load ptr, ptr %23, align 8
  call void @cJSON_Delete(ptr noundef %24)
  br label %25

25:                                               ; preds = %21, %16, %7
  %26 = load ptr, ptr %2, align 8
  %27 = getelementptr inbounds %struct.cJSON, ptr %26, i32 0, i32 3
  %28 = load i32, ptr %27, align 8
  %29 = and i32 %28, 256
  %30 = icmp ne i32 %29, 0
  br i1 %30, label %43, label %31

31:                                               ; preds = %25
  %32 = load ptr, ptr %2, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 4
  %34 = load ptr, ptr %33, align 8
  %35 = icmp ne ptr %34, null
  br i1 %35, label %36, label %43

36:                                               ; preds = %31
  %37 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %38 = load ptr, ptr %2, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 4
  %40 = load ptr, ptr %39, align 8
  call void %37(ptr noundef %40)
  %41 = load ptr, ptr %2, align 8
  %42 = getelementptr inbounds %struct.cJSON, ptr %41, i32 0, i32 4
  store ptr null, ptr %42, align 8
  br label %43

43:                                               ; preds = %36, %31, %25
  %44 = load ptr, ptr %2, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 3
  %46 = load i32, ptr %45, align 8
  %47 = and i32 %46, 512
  %48 = icmp ne i32 %47, 0
  br i1 %48, label %61, label %49

49:                                               ; preds = %43
  %50 = load ptr, ptr %2, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 7
  %52 = load ptr, ptr %51, align 8
  %53 = icmp ne ptr %52, null
  br i1 %53, label %54, label %61

54:                                               ; preds = %49
  %55 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %56 = load ptr, ptr %2, align 8
  %57 = getelementptr inbounds %struct.cJSON, ptr %56, i32 0, i32 7
  %58 = load ptr, ptr %57, align 8
  call void %55(ptr noundef %58)
  %59 = load ptr, ptr %2, align 8
  %60 = getelementptr inbounds %struct.cJSON, ptr %59, i32 0, i32 7
  store ptr null, ptr %60, align 8
  br label %61

61:                                               ; preds = %54, %49, %43
  %62 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %63 = load ptr, ptr %2, align 8
  call void %62(ptr noundef %63)
  %64 = load ptr, ptr %3, align 8
  store ptr %64, ptr %2, align 8
  br label %4, !llvm.loop !6

65:                                               ; preds = %4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local double @cJSON_SetNumberHelper(ptr noundef %0, double noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca double, align 8
  store ptr %0, ptr %3, align 8
  store double %1, ptr %4, align 8
  %5 = load double, ptr %4, align 8
  %6 = fcmp oge double %5, 0x41DFFFFFFFC00000
  br i1 %6, label %7, label %10

7:                                                ; preds = %2
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 5
  store i32 2147483647, ptr %9, align 8
  br label %22

10:                                               ; preds = %2
  %11 = load double, ptr %4, align 8
  %12 = fcmp ole double %11, 0xC1E0000000000000
  br i1 %12, label %13, label %16

13:                                               ; preds = %10
  %14 = load ptr, ptr %3, align 8
  %15 = getelementptr inbounds %struct.cJSON, ptr %14, i32 0, i32 5
  store i32 -2147483648, ptr %15, align 8
  br label %21

16:                                               ; preds = %10
  %17 = load double, ptr %4, align 8
  %18 = fptosi double %17 to i32
  %19 = load ptr, ptr %3, align 8
  %20 = getelementptr inbounds %struct.cJSON, ptr %19, i32 0, i32 5
  store i32 %18, ptr %20, align 8
  br label %21

21:                                               ; preds = %16, %13
  br label %22

22:                                               ; preds = %21, %7
  %23 = load double, ptr %4, align 8
  %24 = load ptr, ptr %3, align 8
  %25 = getelementptr inbounds %struct.cJSON, ptr %24, i32 0, i32 6
  store double %23, ptr %25, align 8
  ret double %23
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_SetValuestring(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  %8 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %9 = load ptr, ptr %4, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %23, label %11

11:                                               ; preds = %2
  %12 = load ptr, ptr %4, align 8
  %13 = getelementptr inbounds %struct.cJSON, ptr %12, i32 0, i32 3
  %14 = load i32, ptr %13, align 8
  %15 = and i32 %14, 16
  %16 = icmp ne i32 %15, 0
  br i1 %16, label %17, label %23

17:                                               ; preds = %11
  %18 = load ptr, ptr %4, align 8
  %19 = getelementptr inbounds %struct.cJSON, ptr %18, i32 0, i32 3
  %20 = load i32, ptr %19, align 8
  %21 = and i32 %20, 256
  %22 = icmp ne i32 %21, 0
  br i1 %22, label %23, label %24

23:                                               ; preds = %17, %11, %2
  store ptr null, ptr %3, align 8
  br label %89

24:                                               ; preds = %17
  %25 = load ptr, ptr %4, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 4
  %27 = load ptr, ptr %26, align 8
  %28 = icmp eq ptr %27, null
  br i1 %28, label %32, label %29

29:                                               ; preds = %24
  %30 = load ptr, ptr %5, align 8
  %31 = icmp eq ptr %30, null
  br i1 %31, label %32, label %33

32:                                               ; preds = %29, %24
  store ptr null, ptr %3, align 8
  br label %89

33:                                               ; preds = %29
  %34 = load ptr, ptr %5, align 8
  %35 = call i64 @strlen(ptr noundef %34) #9
  store i64 %35, ptr %7, align 8
  %36 = load ptr, ptr %4, align 8
  %37 = getelementptr inbounds %struct.cJSON, ptr %36, i32 0, i32 4
  %38 = load ptr, ptr %37, align 8
  %39 = call i64 @strlen(ptr noundef %38) #9
  store i64 %39, ptr %8, align 8
  %40 = load i64, ptr %7, align 8
  %41 = load i64, ptr %8, align 8
  %42 = icmp ule i64 %40, %41
  br i1 %42, label %43, label %69

43:                                               ; preds = %33
  %44 = load ptr, ptr %5, align 8
  %45 = load i64, ptr %7, align 8
  %46 = getelementptr inbounds i8, ptr %44, i64 %45
  %47 = load ptr, ptr %4, align 8
  %48 = getelementptr inbounds %struct.cJSON, ptr %47, i32 0, i32 4
  %49 = load ptr, ptr %48, align 8
  %50 = icmp ult ptr %46, %49
  br i1 %50, label %60, label %51

51:                                               ; preds = %43
  %52 = load ptr, ptr %4, align 8
  %53 = getelementptr inbounds %struct.cJSON, ptr %52, i32 0, i32 4
  %54 = load ptr, ptr %53, align 8
  %55 = load i64, ptr %8, align 8
  %56 = getelementptr inbounds i8, ptr %54, i64 %55
  %57 = load ptr, ptr %5, align 8
  %58 = icmp ult ptr %56, %57
  br i1 %58, label %60, label %59

59:                                               ; preds = %51
  store ptr null, ptr %3, align 8
  br label %89

60:                                               ; preds = %51, %43
  %61 = load ptr, ptr %4, align 8
  %62 = getelementptr inbounds %struct.cJSON, ptr %61, i32 0, i32 4
  %63 = load ptr, ptr %62, align 8
  %64 = load ptr, ptr %5, align 8
  %65 = call ptr @strcpy(ptr noundef %63, ptr noundef %64) #8
  %66 = load ptr, ptr %4, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 4
  %68 = load ptr, ptr %67, align 8
  store ptr %68, ptr %3, align 8
  br label %89

69:                                               ; preds = %33
  %70 = load ptr, ptr %5, align 8
  %71 = call ptr @cJSON_strdup(ptr noundef %70, ptr noundef @global_hooks)
  store ptr %71, ptr %6, align 8
  %72 = load ptr, ptr %6, align 8
  %73 = icmp eq ptr %72, null
  br i1 %73, label %74, label %75

74:                                               ; preds = %69
  store ptr null, ptr %3, align 8
  br label %89

75:                                               ; preds = %69
  %76 = load ptr, ptr %4, align 8
  %77 = getelementptr inbounds %struct.cJSON, ptr %76, i32 0, i32 4
  %78 = load ptr, ptr %77, align 8
  %79 = icmp ne ptr %78, null
  br i1 %79, label %80, label %84

80:                                               ; preds = %75
  %81 = load ptr, ptr %4, align 8
  %82 = getelementptr inbounds %struct.cJSON, ptr %81, i32 0, i32 4
  %83 = load ptr, ptr %82, align 8
  call void @cJSON_free(ptr noundef %83)
  br label %84

84:                                               ; preds = %80, %75
  %85 = load ptr, ptr %6, align 8
  %86 = load ptr, ptr %4, align 8
  %87 = getelementptr inbounds %struct.cJSON, ptr %86, i32 0, i32 4
  store ptr %85, ptr %87, align 8
  %88 = load ptr, ptr %6, align 8
  store ptr %88, ptr %3, align 8
  br label %89

89:                                               ; preds = %84, %74, %60, %59, %32, %23
  %90 = load ptr, ptr %3, align 8
  ret ptr %90
}

; Function Attrs: nounwind willreturn memory(read)
declare i64 @strlen(ptr noundef) #4

; Function Attrs: nounwind
declare ptr @strcpy(ptr noundef, ptr noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @cJSON_strdup(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %10, label %11

10:                                               ; preds = %2
  store ptr null, ptr %3, align 8
  br label %28

11:                                               ; preds = %2
  %12 = load ptr, ptr %4, align 8
  %13 = call i64 @strlen(ptr noundef %12) #9
  %14 = add i64 %13, 1
  store i64 %14, ptr %6, align 8
  %15 = load ptr, ptr %5, align 8
  %16 = getelementptr inbounds %struct.internal_hooks, ptr %15, i32 0, i32 0
  %17 = load ptr, ptr %16, align 8
  %18 = load i64, ptr %6, align 8
  %19 = call ptr %17(i64 noundef %18)
  store ptr %19, ptr %7, align 8
  %20 = load ptr, ptr %7, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %22, label %23

22:                                               ; preds = %11
  store ptr null, ptr %3, align 8
  br label %28

23:                                               ; preds = %11
  %24 = load ptr, ptr %7, align 8
  %25 = load ptr, ptr %4, align 8
  %26 = load i64, ptr %6, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %24, ptr align 1 %25, i64 %26, i1 false)
  %27 = load ptr, ptr %7, align 8
  store ptr %27, ptr %3, align 8
  br label %28

28:                                               ; preds = %23, %22, %10
  %29 = load ptr, ptr %3, align 8
  ret ptr %29
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_free(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %4 = load ptr, ptr %2, align 8
  call void %3(ptr noundef %4)
  store ptr null, ptr %2, align 8
  ret void
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #5

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_ParseWithOpts(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca i64, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %9 = load ptr, ptr %5, align 8
  %10 = icmp eq ptr null, %9
  br i1 %10, label %11, label %12

11:                                               ; preds = %3
  store ptr null, ptr %4, align 8
  br label %21

12:                                               ; preds = %3
  %13 = load ptr, ptr %5, align 8
  %14 = call i64 @strlen(ptr noundef %13) #9
  %15 = add i64 %14, 1
  store i64 %15, ptr %8, align 8
  %16 = load ptr, ptr %5, align 8
  %17 = load i64, ptr %8, align 8
  %18 = load ptr, ptr %6, align 8
  %19 = load i32, ptr %7, align 4
  %20 = call ptr @cJSON_ParseWithLengthOpts(ptr noundef %16, i64 noundef %17, ptr noundef %18, i32 noundef %19)
  store ptr %20, ptr %4, align 8
  br label %21

21:                                               ; preds = %12, %11
  %22 = load ptr, ptr %4, align 8
  ret ptr %22
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_ParseWithLengthOpts(ptr noundef %0, i64 noundef %1, ptr noundef %2, i32 noundef %3) #0 {
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i32, align 4
  %10 = alloca %struct.parse_buffer, align 8
  %11 = alloca ptr, align 8
  %12 = alloca %struct.error, align 8
  store ptr %0, ptr %6, align 8
  store i64 %1, ptr %7, align 8
  store ptr %2, ptr %8, align 8
  store i32 %3, ptr %9, align 4
  call void @llvm.memset.p0.i64(ptr align 8 %10, i8 0, i64 56, i1 false)
  store ptr null, ptr %11, align 8
  store ptr null, ptr @global_error, align 8
  store i64 0, ptr getelementptr inbounds (%struct.error, ptr @global_error, i32 0, i32 1), align 8
  %13 = load ptr, ptr %6, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %18, label %15

15:                                               ; preds = %4
  %16 = load i64, ptr %7, align 8
  %17 = icmp eq i64 0, %16
  br i1 %17, label %18, label %19

18:                                               ; preds = %15, %4
  br label %71

19:                                               ; preds = %15
  %20 = load ptr, ptr %6, align 8
  %21 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 0
  store ptr %20, ptr %21, align 8
  %22 = load i64, ptr %7, align 8
  %23 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 1
  store i64 %22, ptr %23, align 8
  %24 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  store i64 0, ptr %24, align 8
  %25 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 4
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %25, ptr align 8 @global_hooks, i64 24, i1 false)
  %26 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %26, ptr %11, align 8
  %27 = load ptr, ptr %11, align 8
  %28 = icmp eq ptr %27, null
  br i1 %28, label %29, label %30

29:                                               ; preds = %19
  br label %71

30:                                               ; preds = %19
  %31 = load ptr, ptr %11, align 8
  %32 = call ptr @skip_utf8_bom(ptr noundef %10)
  %33 = call ptr @buffer_skip_whitespace(ptr noundef %32)
  %34 = call i32 @parse_value(ptr noundef %31, ptr noundef %33)
  %35 = icmp ne i32 %34, 0
  br i1 %35, label %37, label %36

36:                                               ; preds = %30
  br label %71

37:                                               ; preds = %30
  %38 = load i32, ptr %9, align 4
  %39 = icmp ne i32 %38, 0
  br i1 %39, label %40, label %59

40:                                               ; preds = %37
  %41 = call ptr @buffer_skip_whitespace(ptr noundef %10)
  %42 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  %43 = load i64, ptr %42, align 8
  %44 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 1
  %45 = load i64, ptr %44, align 8
  %46 = icmp uge i64 %43, %45
  br i1 %46, label %57, label %47

47:                                               ; preds = %40
  %48 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 0
  %49 = load ptr, ptr %48, align 8
  %50 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  %51 = load i64, ptr %50, align 8
  %52 = getelementptr inbounds i8, ptr %49, i64 %51
  %53 = getelementptr inbounds i8, ptr %52, i64 0
  %54 = load i8, ptr %53, align 1
  %55 = zext i8 %54 to i32
  %56 = icmp ne i32 %55, 0
  br i1 %56, label %57, label %58

57:                                               ; preds = %47, %40
  br label %71

58:                                               ; preds = %47
  br label %59

59:                                               ; preds = %58, %37
  %60 = load ptr, ptr %8, align 8
  %61 = icmp ne ptr %60, null
  br i1 %61, label %62, label %69

62:                                               ; preds = %59
  %63 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 0
  %64 = load ptr, ptr %63, align 8
  %65 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  %66 = load i64, ptr %65, align 8
  %67 = getelementptr inbounds i8, ptr %64, i64 %66
  %68 = load ptr, ptr %8, align 8
  store ptr %67, ptr %68, align 8
  br label %69

69:                                               ; preds = %62, %59
  %70 = load ptr, ptr %11, align 8
  store ptr %70, ptr %5, align 8
  br label %114

71:                                               ; preds = %57, %36, %29, %18
  %72 = load ptr, ptr %11, align 8
  %73 = icmp ne ptr %72, null
  br i1 %73, label %74, label %76

74:                                               ; preds = %71
  %75 = load ptr, ptr %11, align 8
  call void @cJSON_Delete(ptr noundef %75)
  br label %76

76:                                               ; preds = %74, %71
  %77 = load ptr, ptr %6, align 8
  %78 = icmp ne ptr %77, null
  br i1 %78, label %79, label %113

79:                                               ; preds = %76
  %80 = load ptr, ptr %6, align 8
  %81 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 0
  store ptr %80, ptr %81, align 8
  %82 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 1
  store i64 0, ptr %82, align 8
  %83 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  %84 = load i64, ptr %83, align 8
  %85 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 1
  %86 = load i64, ptr %85, align 8
  %87 = icmp ult i64 %84, %86
  br i1 %87, label %88, label %92

88:                                               ; preds = %79
  %89 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 2
  %90 = load i64, ptr %89, align 8
  %91 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 1
  store i64 %90, ptr %91, align 8
  br label %102

92:                                               ; preds = %79
  %93 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 1
  %94 = load i64, ptr %93, align 8
  %95 = icmp ugt i64 %94, 0
  br i1 %95, label %96, label %101

96:                                               ; preds = %92
  %97 = getelementptr inbounds %struct.parse_buffer, ptr %10, i32 0, i32 1
  %98 = load i64, ptr %97, align 8
  %99 = sub i64 %98, 1
  %100 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 1
  store i64 %99, ptr %100, align 8
  br label %101

101:                                              ; preds = %96, %92
  br label %102

102:                                              ; preds = %101, %88
  %103 = load ptr, ptr %8, align 8
  %104 = icmp ne ptr %103, null
  br i1 %104, label %105, label %112

105:                                              ; preds = %102
  %106 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 0
  %107 = load ptr, ptr %106, align 8
  %108 = getelementptr inbounds %struct.error, ptr %12, i32 0, i32 1
  %109 = load i64, ptr %108, align 8
  %110 = getelementptr inbounds i8, ptr %107, i64 %109
  %111 = load ptr, ptr %8, align 8
  store ptr %110, ptr %111, align 8
  br label %112

112:                                              ; preds = %105, %102
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 @global_error, ptr align 8 %12, i64 16, i1 false)
  br label %113

113:                                              ; preds = %112, %76
  store ptr null, ptr %5, align 8
  br label %114

114:                                              ; preds = %113, %69
  %115 = load ptr, ptr %5, align 8
  ret ptr %115
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #6

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @cJSON_New_Item(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  %5 = getelementptr inbounds %struct.internal_hooks, ptr %4, i32 0, i32 0
  %6 = load ptr, ptr %5, align 8
  %7 = call ptr %6(i64 noundef 64)
  store ptr %7, ptr %3, align 8
  %8 = load ptr, ptr %3, align 8
  %9 = icmp ne ptr %8, null
  br i1 %9, label %10, label %12

10:                                               ; preds = %1
  %11 = load ptr, ptr %3, align 8
  call void @llvm.memset.p0.i64(ptr align 8 %11, i8 0, i64 64, i1 false)
  br label %12

12:                                               ; preds = %10, %1
  %13 = load ptr, ptr %3, align 8
  ret ptr %13
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @skip_utf8_bom(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %16, label %6

6:                                                ; preds = %1
  %7 = load ptr, ptr %3, align 8
  %8 = getelementptr inbounds %struct.parse_buffer, ptr %7, i32 0, i32 0
  %9 = load ptr, ptr %8, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %16, label %11

11:                                               ; preds = %6
  %12 = load ptr, ptr %3, align 8
  %13 = getelementptr inbounds %struct.parse_buffer, ptr %12, i32 0, i32 2
  %14 = load i64, ptr %13, align 8
  %15 = icmp ne i64 %14, 0
  br i1 %15, label %16, label %17

16:                                               ; preds = %11, %6, %1
  store ptr null, ptr %2, align 8
  br label %46

17:                                               ; preds = %11
  %18 = load ptr, ptr %3, align 8
  %19 = icmp ne ptr %18, null
  br i1 %19, label %20, label %44

20:                                               ; preds = %17
  %21 = load ptr, ptr %3, align 8
  %22 = getelementptr inbounds %struct.parse_buffer, ptr %21, i32 0, i32 2
  %23 = load i64, ptr %22, align 8
  %24 = add i64 %23, 4
  %25 = load ptr, ptr %3, align 8
  %26 = getelementptr inbounds %struct.parse_buffer, ptr %25, i32 0, i32 1
  %27 = load i64, ptr %26, align 8
  %28 = icmp ult i64 %24, %27
  br i1 %28, label %29, label %44

29:                                               ; preds = %20
  %30 = load ptr, ptr %3, align 8
  %31 = getelementptr inbounds %struct.parse_buffer, ptr %30, i32 0, i32 0
  %32 = load ptr, ptr %31, align 8
  %33 = load ptr, ptr %3, align 8
  %34 = getelementptr inbounds %struct.parse_buffer, ptr %33, i32 0, i32 2
  %35 = load i64, ptr %34, align 8
  %36 = getelementptr inbounds i8, ptr %32, i64 %35
  %37 = call i32 @strncmp(ptr noundef %36, ptr noundef @.str.1, i64 noundef 3) #9
  %38 = icmp eq i32 %37, 0
  br i1 %38, label %39, label %44

39:                                               ; preds = %29
  %40 = load ptr, ptr %3, align 8
  %41 = getelementptr inbounds %struct.parse_buffer, ptr %40, i32 0, i32 2
  %42 = load i64, ptr %41, align 8
  %43 = add i64 %42, 3
  store i64 %43, ptr %41, align 8
  br label %44

44:                                               ; preds = %39, %29, %20, %17
  %45 = load ptr, ptr %3, align 8
  store ptr %45, ptr %2, align 8
  br label %46

46:                                               ; preds = %44, %16
  %47 = load ptr, ptr %2, align 8
  ret ptr %47
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @buffer_skip_whitespace(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %11, label %6

6:                                                ; preds = %1
  %7 = load ptr, ptr %3, align 8
  %8 = getelementptr inbounds %struct.parse_buffer, ptr %7, i32 0, i32 0
  %9 = load ptr, ptr %8, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %11, label %12

11:                                               ; preds = %6, %1
  store ptr null, ptr %2, align 8
  br label %73

12:                                               ; preds = %6
  %13 = load ptr, ptr %3, align 8
  %14 = icmp ne ptr %13, null
  br i1 %14, label %15, label %24

15:                                               ; preds = %12
  %16 = load ptr, ptr %3, align 8
  %17 = getelementptr inbounds %struct.parse_buffer, ptr %16, i32 0, i32 2
  %18 = load i64, ptr %17, align 8
  %19 = add i64 %18, 0
  %20 = load ptr, ptr %3, align 8
  %21 = getelementptr inbounds %struct.parse_buffer, ptr %20, i32 0, i32 1
  %22 = load i64, ptr %21, align 8
  %23 = icmp ult i64 %19, %22
  br i1 %23, label %26, label %24

24:                                               ; preds = %15, %12
  %25 = load ptr, ptr %3, align 8
  store ptr %25, ptr %2, align 8
  br label %73

26:                                               ; preds = %15
  br label %27

27:                                               ; preds = %53, %26
  %28 = load ptr, ptr %3, align 8
  %29 = icmp ne ptr %28, null
  br i1 %29, label %30, label %51

30:                                               ; preds = %27
  %31 = load ptr, ptr %3, align 8
  %32 = getelementptr inbounds %struct.parse_buffer, ptr %31, i32 0, i32 2
  %33 = load i64, ptr %32, align 8
  %34 = add i64 %33, 0
  %35 = load ptr, ptr %3, align 8
  %36 = getelementptr inbounds %struct.parse_buffer, ptr %35, i32 0, i32 1
  %37 = load i64, ptr %36, align 8
  %38 = icmp ult i64 %34, %37
  br i1 %38, label %39, label %51

39:                                               ; preds = %30
  %40 = load ptr, ptr %3, align 8
  %41 = getelementptr inbounds %struct.parse_buffer, ptr %40, i32 0, i32 0
  %42 = load ptr, ptr %41, align 8
  %43 = load ptr, ptr %3, align 8
  %44 = getelementptr inbounds %struct.parse_buffer, ptr %43, i32 0, i32 2
  %45 = load i64, ptr %44, align 8
  %46 = getelementptr inbounds i8, ptr %42, i64 %45
  %47 = getelementptr inbounds i8, ptr %46, i64 0
  %48 = load i8, ptr %47, align 1
  %49 = zext i8 %48 to i32
  %50 = icmp sle i32 %49, 32
  br label %51

51:                                               ; preds = %39, %30, %27
  %52 = phi i1 [ false, %30 ], [ false, %27 ], [ %50, %39 ]
  br i1 %52, label %53, label %58

53:                                               ; preds = %51
  %54 = load ptr, ptr %3, align 8
  %55 = getelementptr inbounds %struct.parse_buffer, ptr %54, i32 0, i32 2
  %56 = load i64, ptr %55, align 8
  %57 = add i64 %56, 1
  store i64 %57, ptr %55, align 8
  br label %27, !llvm.loop !8

58:                                               ; preds = %51
  %59 = load ptr, ptr %3, align 8
  %60 = getelementptr inbounds %struct.parse_buffer, ptr %59, i32 0, i32 2
  %61 = load i64, ptr %60, align 8
  %62 = load ptr, ptr %3, align 8
  %63 = getelementptr inbounds %struct.parse_buffer, ptr %62, i32 0, i32 1
  %64 = load i64, ptr %63, align 8
  %65 = icmp eq i64 %61, %64
  br i1 %65, label %66, label %71

66:                                               ; preds = %58
  %67 = load ptr, ptr %3, align 8
  %68 = getelementptr inbounds %struct.parse_buffer, ptr %67, i32 0, i32 2
  %69 = load i64, ptr %68, align 8
  %70 = add i64 %69, -1
  store i64 %70, ptr %68, align 8
  br label %71

71:                                               ; preds = %66, %58
  %72 = load ptr, ptr %3, align 8
  store ptr %72, ptr %2, align 8
  br label %73

73:                                               ; preds = %71, %24, %11
  %74 = load ptr, ptr %2, align 8
  ret ptr %74
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_value(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %6 = load ptr, ptr %5, align 8
  %7 = icmp eq ptr %6, null
  br i1 %7, label %13, label %8

8:                                                ; preds = %2
  %9 = load ptr, ptr %5, align 8
  %10 = getelementptr inbounds %struct.parse_buffer, ptr %9, i32 0, i32 0
  %11 = load ptr, ptr %10, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %8, %2
  store i32 0, ptr %3, align 4
  br label %240

14:                                               ; preds = %8
  %15 = load ptr, ptr %5, align 8
  %16 = icmp ne ptr %15, null
  br i1 %16, label %17, label %43

17:                                               ; preds = %14
  %18 = load ptr, ptr %5, align 8
  %19 = getelementptr inbounds %struct.parse_buffer, ptr %18, i32 0, i32 2
  %20 = load i64, ptr %19, align 8
  %21 = add i64 %20, 4
  %22 = load ptr, ptr %5, align 8
  %23 = getelementptr inbounds %struct.parse_buffer, ptr %22, i32 0, i32 1
  %24 = load i64, ptr %23, align 8
  %25 = icmp ule i64 %21, %24
  br i1 %25, label %26, label %43

26:                                               ; preds = %17
  %27 = load ptr, ptr %5, align 8
  %28 = getelementptr inbounds %struct.parse_buffer, ptr %27, i32 0, i32 0
  %29 = load ptr, ptr %28, align 8
  %30 = load ptr, ptr %5, align 8
  %31 = getelementptr inbounds %struct.parse_buffer, ptr %30, i32 0, i32 2
  %32 = load i64, ptr %31, align 8
  %33 = getelementptr inbounds i8, ptr %29, i64 %32
  %34 = call i32 @strncmp(ptr noundef %33, ptr noundef @.str.2, i64 noundef 4) #9
  %35 = icmp eq i32 %34, 0
  br i1 %35, label %36, label %43

36:                                               ; preds = %26
  %37 = load ptr, ptr %4, align 8
  %38 = getelementptr inbounds %struct.cJSON, ptr %37, i32 0, i32 3
  store i32 4, ptr %38, align 8
  %39 = load ptr, ptr %5, align 8
  %40 = getelementptr inbounds %struct.parse_buffer, ptr %39, i32 0, i32 2
  %41 = load i64, ptr %40, align 8
  %42 = add i64 %41, 4
  store i64 %42, ptr %40, align 8
  store i32 1, ptr %3, align 4
  br label %240

43:                                               ; preds = %26, %17, %14
  %44 = load ptr, ptr %5, align 8
  %45 = icmp ne ptr %44, null
  br i1 %45, label %46, label %72

46:                                               ; preds = %43
  %47 = load ptr, ptr %5, align 8
  %48 = getelementptr inbounds %struct.parse_buffer, ptr %47, i32 0, i32 2
  %49 = load i64, ptr %48, align 8
  %50 = add i64 %49, 5
  %51 = load ptr, ptr %5, align 8
  %52 = getelementptr inbounds %struct.parse_buffer, ptr %51, i32 0, i32 1
  %53 = load i64, ptr %52, align 8
  %54 = icmp ule i64 %50, %53
  br i1 %54, label %55, label %72

55:                                               ; preds = %46
  %56 = load ptr, ptr %5, align 8
  %57 = getelementptr inbounds %struct.parse_buffer, ptr %56, i32 0, i32 0
  %58 = load ptr, ptr %57, align 8
  %59 = load ptr, ptr %5, align 8
  %60 = getelementptr inbounds %struct.parse_buffer, ptr %59, i32 0, i32 2
  %61 = load i64, ptr %60, align 8
  %62 = getelementptr inbounds i8, ptr %58, i64 %61
  %63 = call i32 @strncmp(ptr noundef %62, ptr noundef @.str.3, i64 noundef 5) #9
  %64 = icmp eq i32 %63, 0
  br i1 %64, label %65, label %72

65:                                               ; preds = %55
  %66 = load ptr, ptr %4, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 3
  store i32 1, ptr %67, align 8
  %68 = load ptr, ptr %5, align 8
  %69 = getelementptr inbounds %struct.parse_buffer, ptr %68, i32 0, i32 2
  %70 = load i64, ptr %69, align 8
  %71 = add i64 %70, 5
  store i64 %71, ptr %69, align 8
  store i32 1, ptr %3, align 4
  br label %240

72:                                               ; preds = %55, %46, %43
  %73 = load ptr, ptr %5, align 8
  %74 = icmp ne ptr %73, null
  br i1 %74, label %75, label %103

75:                                               ; preds = %72
  %76 = load ptr, ptr %5, align 8
  %77 = getelementptr inbounds %struct.parse_buffer, ptr %76, i32 0, i32 2
  %78 = load i64, ptr %77, align 8
  %79 = add i64 %78, 4
  %80 = load ptr, ptr %5, align 8
  %81 = getelementptr inbounds %struct.parse_buffer, ptr %80, i32 0, i32 1
  %82 = load i64, ptr %81, align 8
  %83 = icmp ule i64 %79, %82
  br i1 %83, label %84, label %103

84:                                               ; preds = %75
  %85 = load ptr, ptr %5, align 8
  %86 = getelementptr inbounds %struct.parse_buffer, ptr %85, i32 0, i32 0
  %87 = load ptr, ptr %86, align 8
  %88 = load ptr, ptr %5, align 8
  %89 = getelementptr inbounds %struct.parse_buffer, ptr %88, i32 0, i32 2
  %90 = load i64, ptr %89, align 8
  %91 = getelementptr inbounds i8, ptr %87, i64 %90
  %92 = call i32 @strncmp(ptr noundef %91, ptr noundef @.str.4, i64 noundef 4) #9
  %93 = icmp eq i32 %92, 0
  br i1 %93, label %94, label %103

94:                                               ; preds = %84
  %95 = load ptr, ptr %4, align 8
  %96 = getelementptr inbounds %struct.cJSON, ptr %95, i32 0, i32 3
  store i32 2, ptr %96, align 8
  %97 = load ptr, ptr %4, align 8
  %98 = getelementptr inbounds %struct.cJSON, ptr %97, i32 0, i32 5
  store i32 1, ptr %98, align 8
  %99 = load ptr, ptr %5, align 8
  %100 = getelementptr inbounds %struct.parse_buffer, ptr %99, i32 0, i32 2
  %101 = load i64, ptr %100, align 8
  %102 = add i64 %101, 4
  store i64 %102, ptr %100, align 8
  store i32 1, ptr %3, align 4
  br label %240

103:                                              ; preds = %84, %75, %72
  %104 = load ptr, ptr %5, align 8
  %105 = icmp ne ptr %104, null
  br i1 %105, label %106, label %131

106:                                              ; preds = %103
  %107 = load ptr, ptr %5, align 8
  %108 = getelementptr inbounds %struct.parse_buffer, ptr %107, i32 0, i32 2
  %109 = load i64, ptr %108, align 8
  %110 = add i64 %109, 0
  %111 = load ptr, ptr %5, align 8
  %112 = getelementptr inbounds %struct.parse_buffer, ptr %111, i32 0, i32 1
  %113 = load i64, ptr %112, align 8
  %114 = icmp ult i64 %110, %113
  br i1 %114, label %115, label %131

115:                                              ; preds = %106
  %116 = load ptr, ptr %5, align 8
  %117 = getelementptr inbounds %struct.parse_buffer, ptr %116, i32 0, i32 0
  %118 = load ptr, ptr %117, align 8
  %119 = load ptr, ptr %5, align 8
  %120 = getelementptr inbounds %struct.parse_buffer, ptr %119, i32 0, i32 2
  %121 = load i64, ptr %120, align 8
  %122 = getelementptr inbounds i8, ptr %118, i64 %121
  %123 = getelementptr inbounds i8, ptr %122, i64 0
  %124 = load i8, ptr %123, align 1
  %125 = zext i8 %124 to i32
  %126 = icmp eq i32 %125, 34
  br i1 %126, label %127, label %131

127:                                              ; preds = %115
  %128 = load ptr, ptr %4, align 8
  %129 = load ptr, ptr %5, align 8
  %130 = call i32 @parse_string(ptr noundef %128, ptr noundef %129)
  store i32 %130, ptr %3, align 4
  br label %240

131:                                              ; preds = %115, %106, %103
  %132 = load ptr, ptr %5, align 8
  %133 = icmp ne ptr %132, null
  br i1 %133, label %134, label %183

134:                                              ; preds = %131
  %135 = load ptr, ptr %5, align 8
  %136 = getelementptr inbounds %struct.parse_buffer, ptr %135, i32 0, i32 2
  %137 = load i64, ptr %136, align 8
  %138 = add i64 %137, 0
  %139 = load ptr, ptr %5, align 8
  %140 = getelementptr inbounds %struct.parse_buffer, ptr %139, i32 0, i32 1
  %141 = load i64, ptr %140, align 8
  %142 = icmp ult i64 %138, %141
  br i1 %142, label %143, label %183

143:                                              ; preds = %134
  %144 = load ptr, ptr %5, align 8
  %145 = getelementptr inbounds %struct.parse_buffer, ptr %144, i32 0, i32 0
  %146 = load ptr, ptr %145, align 8
  %147 = load ptr, ptr %5, align 8
  %148 = getelementptr inbounds %struct.parse_buffer, ptr %147, i32 0, i32 2
  %149 = load i64, ptr %148, align 8
  %150 = getelementptr inbounds i8, ptr %146, i64 %149
  %151 = getelementptr inbounds i8, ptr %150, i64 0
  %152 = load i8, ptr %151, align 1
  %153 = zext i8 %152 to i32
  %154 = icmp eq i32 %153, 45
  br i1 %154, label %179, label %155

155:                                              ; preds = %143
  %156 = load ptr, ptr %5, align 8
  %157 = getelementptr inbounds %struct.parse_buffer, ptr %156, i32 0, i32 0
  %158 = load ptr, ptr %157, align 8
  %159 = load ptr, ptr %5, align 8
  %160 = getelementptr inbounds %struct.parse_buffer, ptr %159, i32 0, i32 2
  %161 = load i64, ptr %160, align 8
  %162 = getelementptr inbounds i8, ptr %158, i64 %161
  %163 = getelementptr inbounds i8, ptr %162, i64 0
  %164 = load i8, ptr %163, align 1
  %165 = zext i8 %164 to i32
  %166 = icmp sge i32 %165, 48
  br i1 %166, label %167, label %183

167:                                              ; preds = %155
  %168 = load ptr, ptr %5, align 8
  %169 = getelementptr inbounds %struct.parse_buffer, ptr %168, i32 0, i32 0
  %170 = load ptr, ptr %169, align 8
  %171 = load ptr, ptr %5, align 8
  %172 = getelementptr inbounds %struct.parse_buffer, ptr %171, i32 0, i32 2
  %173 = load i64, ptr %172, align 8
  %174 = getelementptr inbounds i8, ptr %170, i64 %173
  %175 = getelementptr inbounds i8, ptr %174, i64 0
  %176 = load i8, ptr %175, align 1
  %177 = zext i8 %176 to i32
  %178 = icmp sle i32 %177, 57
  br i1 %178, label %179, label %183

179:                                              ; preds = %167, %143
  %180 = load ptr, ptr %4, align 8
  %181 = load ptr, ptr %5, align 8
  %182 = call i32 @parse_number(ptr noundef %180, ptr noundef %181)
  store i32 %182, ptr %3, align 4
  br label %240

183:                                              ; preds = %167, %155, %134, %131
  %184 = load ptr, ptr %5, align 8
  %185 = icmp ne ptr %184, null
  br i1 %185, label %186, label %211

186:                                              ; preds = %183
  %187 = load ptr, ptr %5, align 8
  %188 = getelementptr inbounds %struct.parse_buffer, ptr %187, i32 0, i32 2
  %189 = load i64, ptr %188, align 8
  %190 = add i64 %189, 0
  %191 = load ptr, ptr %5, align 8
  %192 = getelementptr inbounds %struct.parse_buffer, ptr %191, i32 0, i32 1
  %193 = load i64, ptr %192, align 8
  %194 = icmp ult i64 %190, %193
  br i1 %194, label %195, label %211

195:                                              ; preds = %186
  %196 = load ptr, ptr %5, align 8
  %197 = getelementptr inbounds %struct.parse_buffer, ptr %196, i32 0, i32 0
  %198 = load ptr, ptr %197, align 8
  %199 = load ptr, ptr %5, align 8
  %200 = getelementptr inbounds %struct.parse_buffer, ptr %199, i32 0, i32 2
  %201 = load i64, ptr %200, align 8
  %202 = getelementptr inbounds i8, ptr %198, i64 %201
  %203 = getelementptr inbounds i8, ptr %202, i64 0
  %204 = load i8, ptr %203, align 1
  %205 = zext i8 %204 to i32
  %206 = icmp eq i32 %205, 91
  br i1 %206, label %207, label %211

207:                                              ; preds = %195
  %208 = load ptr, ptr %4, align 8
  %209 = load ptr, ptr %5, align 8
  %210 = call i32 @parse_array(ptr noundef %208, ptr noundef %209)
  store i32 %210, ptr %3, align 4
  br label %240

211:                                              ; preds = %195, %186, %183
  %212 = load ptr, ptr %5, align 8
  %213 = icmp ne ptr %212, null
  br i1 %213, label %214, label %239

214:                                              ; preds = %211
  %215 = load ptr, ptr %5, align 8
  %216 = getelementptr inbounds %struct.parse_buffer, ptr %215, i32 0, i32 2
  %217 = load i64, ptr %216, align 8
  %218 = add i64 %217, 0
  %219 = load ptr, ptr %5, align 8
  %220 = getelementptr inbounds %struct.parse_buffer, ptr %219, i32 0, i32 1
  %221 = load i64, ptr %220, align 8
  %222 = icmp ult i64 %218, %221
  br i1 %222, label %223, label %239

223:                                              ; preds = %214
  %224 = load ptr, ptr %5, align 8
  %225 = getelementptr inbounds %struct.parse_buffer, ptr %224, i32 0, i32 0
  %226 = load ptr, ptr %225, align 8
  %227 = load ptr, ptr %5, align 8
  %228 = getelementptr inbounds %struct.parse_buffer, ptr %227, i32 0, i32 2
  %229 = load i64, ptr %228, align 8
  %230 = getelementptr inbounds i8, ptr %226, i64 %229
  %231 = getelementptr inbounds i8, ptr %230, i64 0
  %232 = load i8, ptr %231, align 1
  %233 = zext i8 %232 to i32
  %234 = icmp eq i32 %233, 123
  br i1 %234, label %235, label %239

235:                                              ; preds = %223
  %236 = load ptr, ptr %4, align 8
  %237 = load ptr, ptr %5, align 8
  %238 = call i32 @parse_object(ptr noundef %236, ptr noundef %237)
  store i32 %238, ptr %3, align 4
  br label %240

239:                                              ; preds = %223, %214, %211
  store i32 0, ptr %3, align 4
  br label %240

240:                                              ; preds = %239, %235, %207, %179, %127, %94, %65, %36, %13
  %241 = load i32, ptr %3, align 4
  ret i32 %241
}

; Function Attrs: nounwind willreturn memory(read)
declare i32 @strncmp(ptr noundef, ptr noundef, i64 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_string(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca i64, align 8
  %11 = alloca i64, align 8
  %12 = alloca i8, align 1
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %13 = load ptr, ptr %5, align 8
  %14 = getelementptr inbounds %struct.parse_buffer, ptr %13, i32 0, i32 0
  %15 = load ptr, ptr %14, align 8
  %16 = load ptr, ptr %5, align 8
  %17 = getelementptr inbounds %struct.parse_buffer, ptr %16, i32 0, i32 2
  %18 = load i64, ptr %17, align 8
  %19 = getelementptr inbounds i8, ptr %15, i64 %18
  %20 = getelementptr inbounds i8, ptr %19, i64 1
  store ptr %20, ptr %6, align 8
  %21 = load ptr, ptr %5, align 8
  %22 = getelementptr inbounds %struct.parse_buffer, ptr %21, i32 0, i32 0
  %23 = load ptr, ptr %22, align 8
  %24 = load ptr, ptr %5, align 8
  %25 = getelementptr inbounds %struct.parse_buffer, ptr %24, i32 0, i32 2
  %26 = load i64, ptr %25, align 8
  %27 = getelementptr inbounds i8, ptr %23, i64 %26
  %28 = getelementptr inbounds i8, ptr %27, i64 1
  store ptr %28, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  %29 = load ptr, ptr %5, align 8
  %30 = getelementptr inbounds %struct.parse_buffer, ptr %29, i32 0, i32 0
  %31 = load ptr, ptr %30, align 8
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.parse_buffer, ptr %32, i32 0, i32 2
  %34 = load i64, ptr %33, align 8
  %35 = getelementptr inbounds i8, ptr %31, i64 %34
  %36 = getelementptr inbounds i8, ptr %35, i64 0
  %37 = load i8, ptr %36, align 1
  %38 = zext i8 %37 to i32
  %39 = icmp ne i32 %38, 34
  br i1 %39, label %40, label %41

40:                                               ; preds = %2
  br label %219

41:                                               ; preds = %2
  store i64 0, ptr %10, align 8
  store i64 0, ptr %11, align 8
  br label %42

42:                                               ; preds = %86, %41
  %43 = load ptr, ptr %7, align 8
  %44 = load ptr, ptr %5, align 8
  %45 = getelementptr inbounds %struct.parse_buffer, ptr %44, i32 0, i32 0
  %46 = load ptr, ptr %45, align 8
  %47 = ptrtoint ptr %43 to i64
  %48 = ptrtoint ptr %46 to i64
  %49 = sub i64 %47, %48
  %50 = load ptr, ptr %5, align 8
  %51 = getelementptr inbounds %struct.parse_buffer, ptr %50, i32 0, i32 1
  %52 = load i64, ptr %51, align 8
  %53 = icmp ult i64 %49, %52
  br i1 %53, label %54, label %59

54:                                               ; preds = %42
  %55 = load ptr, ptr %7, align 8
  %56 = load i8, ptr %55, align 1
  %57 = zext i8 %56 to i32
  %58 = icmp ne i32 %57, 34
  br label %59

59:                                               ; preds = %54, %42
  %60 = phi i1 [ false, %42 ], [ %58, %54 ]
  br i1 %60, label %61, label %89

61:                                               ; preds = %59
  %62 = load ptr, ptr %7, align 8
  %63 = getelementptr inbounds i8, ptr %62, i64 0
  %64 = load i8, ptr %63, align 1
  %65 = zext i8 %64 to i32
  %66 = icmp eq i32 %65, 92
  br i1 %66, label %67, label %86

67:                                               ; preds = %61
  %68 = load ptr, ptr %7, align 8
  %69 = getelementptr inbounds i8, ptr %68, i64 1
  %70 = load ptr, ptr %5, align 8
  %71 = getelementptr inbounds %struct.parse_buffer, ptr %70, i32 0, i32 0
  %72 = load ptr, ptr %71, align 8
  %73 = ptrtoint ptr %69 to i64
  %74 = ptrtoint ptr %72 to i64
  %75 = sub i64 %73, %74
  %76 = load ptr, ptr %5, align 8
  %77 = getelementptr inbounds %struct.parse_buffer, ptr %76, i32 0, i32 1
  %78 = load i64, ptr %77, align 8
  %79 = icmp uge i64 %75, %78
  br i1 %79, label %80, label %81

80:                                               ; preds = %67
  br label %219

81:                                               ; preds = %67
  %82 = load i64, ptr %11, align 8
  %83 = add i64 %82, 1
  store i64 %83, ptr %11, align 8
  %84 = load ptr, ptr %7, align 8
  %85 = getelementptr inbounds i8, ptr %84, i32 1
  store ptr %85, ptr %7, align 8
  br label %86

86:                                               ; preds = %81, %61
  %87 = load ptr, ptr %7, align 8
  %88 = getelementptr inbounds i8, ptr %87, i32 1
  store ptr %88, ptr %7, align 8
  br label %42, !llvm.loop !9

89:                                               ; preds = %59
  %90 = load ptr, ptr %7, align 8
  %91 = load ptr, ptr %5, align 8
  %92 = getelementptr inbounds %struct.parse_buffer, ptr %91, i32 0, i32 0
  %93 = load ptr, ptr %92, align 8
  %94 = ptrtoint ptr %90 to i64
  %95 = ptrtoint ptr %93 to i64
  %96 = sub i64 %94, %95
  %97 = load ptr, ptr %5, align 8
  %98 = getelementptr inbounds %struct.parse_buffer, ptr %97, i32 0, i32 1
  %99 = load i64, ptr %98, align 8
  %100 = icmp uge i64 %96, %99
  br i1 %100, label %106, label %101

101:                                              ; preds = %89
  %102 = load ptr, ptr %7, align 8
  %103 = load i8, ptr %102, align 1
  %104 = zext i8 %103 to i32
  %105 = icmp ne i32 %104, 34
  br i1 %105, label %106, label %107

106:                                              ; preds = %101, %89
  br label %219

107:                                              ; preds = %101
  %108 = load ptr, ptr %7, align 8
  %109 = load ptr, ptr %5, align 8
  %110 = getelementptr inbounds %struct.parse_buffer, ptr %109, i32 0, i32 0
  %111 = load ptr, ptr %110, align 8
  %112 = load ptr, ptr %5, align 8
  %113 = getelementptr inbounds %struct.parse_buffer, ptr %112, i32 0, i32 2
  %114 = load i64, ptr %113, align 8
  %115 = getelementptr inbounds i8, ptr %111, i64 %114
  %116 = ptrtoint ptr %108 to i64
  %117 = ptrtoint ptr %115 to i64
  %118 = sub i64 %116, %117
  %119 = load i64, ptr %11, align 8
  %120 = sub i64 %118, %119
  store i64 %120, ptr %10, align 8
  %121 = load ptr, ptr %5, align 8
  %122 = getelementptr inbounds %struct.parse_buffer, ptr %121, i32 0, i32 4
  %123 = getelementptr inbounds %struct.internal_hooks, ptr %122, i32 0, i32 0
  %124 = load ptr, ptr %123, align 8
  %125 = load i64, ptr %10, align 8
  %126 = add i64 %125, 1
  %127 = call ptr %124(i64 noundef %126)
  store ptr %127, ptr %9, align 8
  %128 = load ptr, ptr %9, align 8
  %129 = icmp eq ptr %128, null
  br i1 %129, label %130, label %131

130:                                              ; preds = %107
  br label %219

131:                                              ; preds = %107
  %132 = load ptr, ptr %9, align 8
  store ptr %132, ptr %8, align 8
  br label %133

133:                                              ; preds = %198, %131
  %134 = load ptr, ptr %6, align 8
  %135 = load ptr, ptr %7, align 8
  %136 = icmp ult ptr %134, %135
  br i1 %136, label %137, label %199

137:                                              ; preds = %133
  %138 = load ptr, ptr %6, align 8
  %139 = load i8, ptr %138, align 1
  %140 = zext i8 %139 to i32
  %141 = icmp ne i32 %140, 92
  br i1 %141, label %142, label %148

142:                                              ; preds = %137
  %143 = load ptr, ptr %6, align 8
  %144 = getelementptr inbounds i8, ptr %143, i32 1
  store ptr %144, ptr %6, align 8
  %145 = load i8, ptr %143, align 1
  %146 = load ptr, ptr %8, align 8
  %147 = getelementptr inbounds i8, ptr %146, i32 1
  store ptr %147, ptr %8, align 8
  store i8 %145, ptr %146, align 1
  br label %198

148:                                              ; preds = %137
  store i8 2, ptr %12, align 1
  %149 = load ptr, ptr %7, align 8
  %150 = load ptr, ptr %6, align 8
  %151 = ptrtoint ptr %149 to i64
  %152 = ptrtoint ptr %150 to i64
  %153 = sub i64 %151, %152
  %154 = icmp slt i64 %153, 1
  br i1 %154, label %155, label %156

155:                                              ; preds = %148
  br label %219

156:                                              ; preds = %148
  %157 = load ptr, ptr %6, align 8
  %158 = getelementptr inbounds i8, ptr %157, i64 1
  %159 = load i8, ptr %158, align 1
  %160 = zext i8 %159 to i32
  switch i32 %160, label %191 [
    i32 98, label %161
    i32 102, label %164
    i32 110, label %167
    i32 114, label %170
    i32 116, label %173
    i32 34, label %176
    i32 92, label %176
    i32 47, label %176
    i32 117, label %182
  ]

161:                                              ; preds = %156
  %162 = load ptr, ptr %8, align 8
  %163 = getelementptr inbounds i8, ptr %162, i32 1
  store ptr %163, ptr %8, align 8
  store i8 8, ptr %162, align 1
  br label %192

164:                                              ; preds = %156
  %165 = load ptr, ptr %8, align 8
  %166 = getelementptr inbounds i8, ptr %165, i32 1
  store ptr %166, ptr %8, align 8
  store i8 12, ptr %165, align 1
  br label %192

167:                                              ; preds = %156
  %168 = load ptr, ptr %8, align 8
  %169 = getelementptr inbounds i8, ptr %168, i32 1
  store ptr %169, ptr %8, align 8
  store i8 10, ptr %168, align 1
  br label %192

170:                                              ; preds = %156
  %171 = load ptr, ptr %8, align 8
  %172 = getelementptr inbounds i8, ptr %171, i32 1
  store ptr %172, ptr %8, align 8
  store i8 13, ptr %171, align 1
  br label %192

173:                                              ; preds = %156
  %174 = load ptr, ptr %8, align 8
  %175 = getelementptr inbounds i8, ptr %174, i32 1
  store ptr %175, ptr %8, align 8
  store i8 9, ptr %174, align 1
  br label %192

176:                                              ; preds = %156, %156, %156
  %177 = load ptr, ptr %6, align 8
  %178 = getelementptr inbounds i8, ptr %177, i64 1
  %179 = load i8, ptr %178, align 1
  %180 = load ptr, ptr %8, align 8
  %181 = getelementptr inbounds i8, ptr %180, i32 1
  store ptr %181, ptr %8, align 8
  store i8 %179, ptr %180, align 1
  br label %192

182:                                              ; preds = %156
  %183 = load ptr, ptr %6, align 8
  %184 = load ptr, ptr %7, align 8
  %185 = call i8 @utf16_literal_to_utf8(ptr noundef %183, ptr noundef %184, ptr noundef %8)
  store i8 %185, ptr %12, align 1
  %186 = load i8, ptr %12, align 1
  %187 = zext i8 %186 to i32
  %188 = icmp eq i32 %187, 0
  br i1 %188, label %189, label %190

189:                                              ; preds = %182
  br label %219

190:                                              ; preds = %182
  br label %192

191:                                              ; preds = %156
  br label %219

192:                                              ; preds = %190, %176, %173, %170, %167, %164, %161
  %193 = load i8, ptr %12, align 1
  %194 = zext i8 %193 to i32
  %195 = load ptr, ptr %6, align 8
  %196 = sext i32 %194 to i64
  %197 = getelementptr inbounds i8, ptr %195, i64 %196
  store ptr %197, ptr %6, align 8
  br label %198

198:                                              ; preds = %192, %142
  br label %133, !llvm.loop !10

199:                                              ; preds = %133
  %200 = load ptr, ptr %8, align 8
  store i8 0, ptr %200, align 1
  %201 = load ptr, ptr %4, align 8
  %202 = getelementptr inbounds %struct.cJSON, ptr %201, i32 0, i32 3
  store i32 16, ptr %202, align 8
  %203 = load ptr, ptr %9, align 8
  %204 = load ptr, ptr %4, align 8
  %205 = getelementptr inbounds %struct.cJSON, ptr %204, i32 0, i32 4
  store ptr %203, ptr %205, align 8
  %206 = load ptr, ptr %7, align 8
  %207 = load ptr, ptr %5, align 8
  %208 = getelementptr inbounds %struct.parse_buffer, ptr %207, i32 0, i32 0
  %209 = load ptr, ptr %208, align 8
  %210 = ptrtoint ptr %206 to i64
  %211 = ptrtoint ptr %209 to i64
  %212 = sub i64 %210, %211
  %213 = load ptr, ptr %5, align 8
  %214 = getelementptr inbounds %struct.parse_buffer, ptr %213, i32 0, i32 2
  store i64 %212, ptr %214, align 8
  %215 = load ptr, ptr %5, align 8
  %216 = getelementptr inbounds %struct.parse_buffer, ptr %215, i32 0, i32 2
  %217 = load i64, ptr %216, align 8
  %218 = add i64 %217, 1
  store i64 %218, ptr %216, align 8
  store i32 1, ptr %3, align 4
  br label %242

219:                                              ; preds = %191, %189, %155, %130, %106, %80, %40
  %220 = load ptr, ptr %9, align 8
  %221 = icmp ne ptr %220, null
  br i1 %221, label %222, label %228

222:                                              ; preds = %219
  %223 = load ptr, ptr %5, align 8
  %224 = getelementptr inbounds %struct.parse_buffer, ptr %223, i32 0, i32 4
  %225 = getelementptr inbounds %struct.internal_hooks, ptr %224, i32 0, i32 1
  %226 = load ptr, ptr %225, align 8
  %227 = load ptr, ptr %9, align 8
  call void %226(ptr noundef %227)
  store ptr null, ptr %9, align 8
  br label %228

228:                                              ; preds = %222, %219
  %229 = load ptr, ptr %6, align 8
  %230 = icmp ne ptr %229, null
  br i1 %230, label %231, label %241

231:                                              ; preds = %228
  %232 = load ptr, ptr %6, align 8
  %233 = load ptr, ptr %5, align 8
  %234 = getelementptr inbounds %struct.parse_buffer, ptr %233, i32 0, i32 0
  %235 = load ptr, ptr %234, align 8
  %236 = ptrtoint ptr %232 to i64
  %237 = ptrtoint ptr %235 to i64
  %238 = sub i64 %236, %237
  %239 = load ptr, ptr %5, align 8
  %240 = getelementptr inbounds %struct.parse_buffer, ptr %239, i32 0, i32 2
  store i64 %238, ptr %240, align 8
  br label %241

241:                                              ; preds = %231, %228
  store i32 0, ptr %3, align 4
  br label %242

242:                                              ; preds = %241, %199
  %243 = load i32, ptr %3, align 4
  ret i32 %243
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_number(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca double, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i8, align 1
  %10 = alloca i64, align 8
  %11 = alloca i64, align 8
  %12 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store double 0.000000e+00, ptr %6, align 8
  store ptr null, ptr %7, align 8
  %13 = call i8 @get_decimal_point()
  store i8 %13, ptr %9, align 1
  store i64 0, ptr %10, align 8
  store i64 0, ptr %11, align 8
  store i32 0, ptr %12, align 4
  %14 = load ptr, ptr %5, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %21, label %16

16:                                               ; preds = %2
  %17 = load ptr, ptr %5, align 8
  %18 = getelementptr inbounds %struct.parse_buffer, ptr %17, i32 0, i32 0
  %19 = load ptr, ptr %18, align 8
  %20 = icmp eq ptr %19, null
  br i1 %20, label %21, label %22

21:                                               ; preds = %16, %2
  store i32 0, ptr %3, align 4
  br label %160

22:                                               ; preds = %16
  store i64 0, ptr %10, align 8
  br label %23

23:                                               ; preds = %58, %22
  %24 = load ptr, ptr %5, align 8
  %25 = icmp ne ptr %24, null
  br i1 %25, label %26, label %36

26:                                               ; preds = %23
  %27 = load ptr, ptr %5, align 8
  %28 = getelementptr inbounds %struct.parse_buffer, ptr %27, i32 0, i32 2
  %29 = load i64, ptr %28, align 8
  %30 = load i64, ptr %10, align 8
  %31 = add i64 %29, %30
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.parse_buffer, ptr %32, i32 0, i32 1
  %34 = load i64, ptr %33, align 8
  %35 = icmp ult i64 %31, %34
  br label %36

36:                                               ; preds = %26, %23
  %37 = phi i1 [ false, %23 ], [ %35, %26 ]
  br i1 %37, label %38, label %61

38:                                               ; preds = %36
  %39 = load ptr, ptr %5, align 8
  %40 = getelementptr inbounds %struct.parse_buffer, ptr %39, i32 0, i32 0
  %41 = load ptr, ptr %40, align 8
  %42 = load ptr, ptr %5, align 8
  %43 = getelementptr inbounds %struct.parse_buffer, ptr %42, i32 0, i32 2
  %44 = load i64, ptr %43, align 8
  %45 = getelementptr inbounds i8, ptr %41, i64 %44
  %46 = load i64, ptr %10, align 8
  %47 = getelementptr inbounds i8, ptr %45, i64 %46
  %48 = load i8, ptr %47, align 1
  %49 = zext i8 %48 to i32
  switch i32 %49, label %56 [
    i32 48, label %50
    i32 49, label %50
    i32 50, label %50
    i32 51, label %50
    i32 52, label %50
    i32 53, label %50
    i32 54, label %50
    i32 55, label %50
    i32 56, label %50
    i32 57, label %50
    i32 43, label %50
    i32 45, label %50
    i32 101, label %50
    i32 69, label %50
    i32 46, label %53
  ]

50:                                               ; preds = %38, %38, %38, %38, %38, %38, %38, %38, %38, %38, %38, %38, %38, %38
  %51 = load i64, ptr %11, align 8
  %52 = add i64 %51, 1
  store i64 %52, ptr %11, align 8
  br label %57

53:                                               ; preds = %38
  %54 = load i64, ptr %11, align 8
  %55 = add i64 %54, 1
  store i64 %55, ptr %11, align 8
  store i32 1, ptr %12, align 4
  br label %57

56:                                               ; preds = %38
  br label %62

57:                                               ; preds = %53, %50
  br label %58

58:                                               ; preds = %57
  %59 = load i64, ptr %10, align 8
  %60 = add i64 %59, 1
  store i64 %60, ptr %10, align 8
  br label %23, !llvm.loop !11

61:                                               ; preds = %36
  br label %62

62:                                               ; preds = %61, %56
  %63 = load ptr, ptr %5, align 8
  %64 = getelementptr inbounds %struct.parse_buffer, ptr %63, i32 0, i32 4
  %65 = getelementptr inbounds %struct.internal_hooks, ptr %64, i32 0, i32 0
  %66 = load ptr, ptr %65, align 8
  %67 = load i64, ptr %11, align 8
  %68 = add i64 %67, 1
  %69 = call ptr %66(i64 noundef %68)
  store ptr %69, ptr %8, align 8
  %70 = load ptr, ptr %8, align 8
  %71 = icmp eq ptr %70, null
  br i1 %71, label %72, label %73

72:                                               ; preds = %62
  store i32 0, ptr %3, align 4
  br label %160

73:                                               ; preds = %62
  %74 = load ptr, ptr %8, align 8
  %75 = load ptr, ptr %5, align 8
  %76 = getelementptr inbounds %struct.parse_buffer, ptr %75, i32 0, i32 0
  %77 = load ptr, ptr %76, align 8
  %78 = load ptr, ptr %5, align 8
  %79 = getelementptr inbounds %struct.parse_buffer, ptr %78, i32 0, i32 2
  %80 = load i64, ptr %79, align 8
  %81 = getelementptr inbounds i8, ptr %77, i64 %80
  %82 = load i64, ptr %11, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %74, ptr align 1 %81, i64 %82, i1 false)
  %83 = load ptr, ptr %8, align 8
  %84 = load i64, ptr %11, align 8
  %85 = getelementptr inbounds i8, ptr %83, i64 %84
  store i8 0, ptr %85, align 1
  %86 = load i32, ptr %12, align 4
  %87 = icmp ne i32 %86, 0
  br i1 %87, label %88, label %110

88:                                               ; preds = %73
  store i64 0, ptr %10, align 8
  br label %89

89:                                               ; preds = %106, %88
  %90 = load i64, ptr %10, align 8
  %91 = load i64, ptr %11, align 8
  %92 = icmp ult i64 %90, %91
  br i1 %92, label %93, label %109

93:                                               ; preds = %89
  %94 = load ptr, ptr %8, align 8
  %95 = load i64, ptr %10, align 8
  %96 = getelementptr inbounds i8, ptr %94, i64 %95
  %97 = load i8, ptr %96, align 1
  %98 = zext i8 %97 to i32
  %99 = icmp eq i32 %98, 46
  br i1 %99, label %100, label %105

100:                                              ; preds = %93
  %101 = load i8, ptr %9, align 1
  %102 = load ptr, ptr %8, align 8
  %103 = load i64, ptr %10, align 8
  %104 = getelementptr inbounds i8, ptr %102, i64 %103
  store i8 %101, ptr %104, align 1
  br label %105

105:                                              ; preds = %100, %93
  br label %106

106:                                              ; preds = %105
  %107 = load i64, ptr %10, align 8
  %108 = add i64 %107, 1
  store i64 %108, ptr %10, align 8
  br label %89, !llvm.loop !12

109:                                              ; preds = %89
  br label %110

110:                                              ; preds = %109, %73
  %111 = load ptr, ptr %8, align 8
  %112 = call double @strtod(ptr noundef %111, ptr noundef %7) #8
  store double %112, ptr %6, align 8
  %113 = load ptr, ptr %8, align 8
  %114 = load ptr, ptr %7, align 8
  %115 = icmp eq ptr %113, %114
  br i1 %115, label %116, label %122

116:                                              ; preds = %110
  %117 = load ptr, ptr %5, align 8
  %118 = getelementptr inbounds %struct.parse_buffer, ptr %117, i32 0, i32 4
  %119 = getelementptr inbounds %struct.internal_hooks, ptr %118, i32 0, i32 1
  %120 = load ptr, ptr %119, align 8
  %121 = load ptr, ptr %8, align 8
  call void %120(ptr noundef %121)
  store i32 0, ptr %3, align 4
  br label %160

122:                                              ; preds = %110
  %123 = load double, ptr %6, align 8
  %124 = load ptr, ptr %4, align 8
  %125 = getelementptr inbounds %struct.cJSON, ptr %124, i32 0, i32 6
  store double %123, ptr %125, align 8
  %126 = load double, ptr %6, align 8
  %127 = fcmp oge double %126, 0x41DFFFFFFFC00000
  br i1 %127, label %128, label %131

128:                                              ; preds = %122
  %129 = load ptr, ptr %4, align 8
  %130 = getelementptr inbounds %struct.cJSON, ptr %129, i32 0, i32 5
  store i32 2147483647, ptr %130, align 8
  br label %143

131:                                              ; preds = %122
  %132 = load double, ptr %6, align 8
  %133 = fcmp ole double %132, 0xC1E0000000000000
  br i1 %133, label %134, label %137

134:                                              ; preds = %131
  %135 = load ptr, ptr %4, align 8
  %136 = getelementptr inbounds %struct.cJSON, ptr %135, i32 0, i32 5
  store i32 -2147483648, ptr %136, align 8
  br label %142

137:                                              ; preds = %131
  %138 = load double, ptr %6, align 8
  %139 = fptosi double %138 to i32
  %140 = load ptr, ptr %4, align 8
  %141 = getelementptr inbounds %struct.cJSON, ptr %140, i32 0, i32 5
  store i32 %139, ptr %141, align 8
  br label %142

142:                                              ; preds = %137, %134
  br label %143

143:                                              ; preds = %142, %128
  %144 = load ptr, ptr %4, align 8
  %145 = getelementptr inbounds %struct.cJSON, ptr %144, i32 0, i32 3
  store i32 8, ptr %145, align 8
  %146 = load ptr, ptr %7, align 8
  %147 = load ptr, ptr %8, align 8
  %148 = ptrtoint ptr %146 to i64
  %149 = ptrtoint ptr %147 to i64
  %150 = sub i64 %148, %149
  %151 = load ptr, ptr %5, align 8
  %152 = getelementptr inbounds %struct.parse_buffer, ptr %151, i32 0, i32 2
  %153 = load i64, ptr %152, align 8
  %154 = add i64 %153, %150
  store i64 %154, ptr %152, align 8
  %155 = load ptr, ptr %5, align 8
  %156 = getelementptr inbounds %struct.parse_buffer, ptr %155, i32 0, i32 4
  %157 = getelementptr inbounds %struct.internal_hooks, ptr %156, i32 0, i32 1
  %158 = load ptr, ptr %157, align 8
  %159 = load ptr, ptr %8, align 8
  call void %158(ptr noundef %159)
  store i32 1, ptr %3, align 4
  br label %160

160:                                              ; preds = %143, %116, %72, %21
  %161 = load i32, ptr %3, align 4
  ret i32 %161
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_array(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store ptr null, ptr %7, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = getelementptr inbounds %struct.parse_buffer, ptr %9, i32 0, i32 3
  %11 = load i64, ptr %10, align 8
  %12 = icmp uge i64 %11, 1000
  br i1 %12, label %13, label %14

13:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %198

14:                                               ; preds = %2
  %15 = load ptr, ptr %5, align 8
  %16 = getelementptr inbounds %struct.parse_buffer, ptr %15, i32 0, i32 3
  %17 = load i64, ptr %16, align 8
  %18 = add i64 %17, 1
  store i64 %18, ptr %16, align 8
  %19 = load ptr, ptr %5, align 8
  %20 = getelementptr inbounds %struct.parse_buffer, ptr %19, i32 0, i32 0
  %21 = load ptr, ptr %20, align 8
  %22 = load ptr, ptr %5, align 8
  %23 = getelementptr inbounds %struct.parse_buffer, ptr %22, i32 0, i32 2
  %24 = load i64, ptr %23, align 8
  %25 = getelementptr inbounds i8, ptr %21, i64 %24
  %26 = getelementptr inbounds i8, ptr %25, i64 0
  %27 = load i8, ptr %26, align 1
  %28 = zext i8 %27 to i32
  %29 = icmp ne i32 %28, 91
  br i1 %29, label %30, label %31

30:                                               ; preds = %14
  br label %192

31:                                               ; preds = %14
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.parse_buffer, ptr %32, i32 0, i32 2
  %34 = load i64, ptr %33, align 8
  %35 = add i64 %34, 1
  store i64 %35, ptr %33, align 8
  %36 = load ptr, ptr %5, align 8
  %37 = call ptr @buffer_skip_whitespace(ptr noundef %36)
  %38 = load ptr, ptr %5, align 8
  %39 = icmp ne ptr %38, null
  br i1 %39, label %40, label %62

40:                                               ; preds = %31
  %41 = load ptr, ptr %5, align 8
  %42 = getelementptr inbounds %struct.parse_buffer, ptr %41, i32 0, i32 2
  %43 = load i64, ptr %42, align 8
  %44 = add i64 %43, 0
  %45 = load ptr, ptr %5, align 8
  %46 = getelementptr inbounds %struct.parse_buffer, ptr %45, i32 0, i32 1
  %47 = load i64, ptr %46, align 8
  %48 = icmp ult i64 %44, %47
  br i1 %48, label %49, label %62

49:                                               ; preds = %40
  %50 = load ptr, ptr %5, align 8
  %51 = getelementptr inbounds %struct.parse_buffer, ptr %50, i32 0, i32 0
  %52 = load ptr, ptr %51, align 8
  %53 = load ptr, ptr %5, align 8
  %54 = getelementptr inbounds %struct.parse_buffer, ptr %53, i32 0, i32 2
  %55 = load i64, ptr %54, align 8
  %56 = getelementptr inbounds i8, ptr %52, i64 %55
  %57 = getelementptr inbounds i8, ptr %56, i64 0
  %58 = load i8, ptr %57, align 1
  %59 = zext i8 %58 to i32
  %60 = icmp eq i32 %59, 93
  br i1 %60, label %61, label %62

61:                                               ; preds = %49
  br label %171

62:                                               ; preds = %49, %40, %31
  %63 = load ptr, ptr %5, align 8
  %64 = icmp ne ptr %63, null
  br i1 %64, label %65, label %74

65:                                               ; preds = %62
  %66 = load ptr, ptr %5, align 8
  %67 = getelementptr inbounds %struct.parse_buffer, ptr %66, i32 0, i32 2
  %68 = load i64, ptr %67, align 8
  %69 = add i64 %68, 0
  %70 = load ptr, ptr %5, align 8
  %71 = getelementptr inbounds %struct.parse_buffer, ptr %70, i32 0, i32 1
  %72 = load i64, ptr %71, align 8
  %73 = icmp ult i64 %69, %72
  br i1 %73, label %79, label %74

74:                                               ; preds = %65, %62
  %75 = load ptr, ptr %5, align 8
  %76 = getelementptr inbounds %struct.parse_buffer, ptr %75, i32 0, i32 2
  %77 = load i64, ptr %76, align 8
  %78 = add i64 %77, -1
  store i64 %78, ptr %76, align 8
  br label %192

79:                                               ; preds = %65
  %80 = load ptr, ptr %5, align 8
  %81 = getelementptr inbounds %struct.parse_buffer, ptr %80, i32 0, i32 2
  %82 = load i64, ptr %81, align 8
  %83 = add i64 %82, -1
  store i64 %83, ptr %81, align 8
  br label %84

84:                                               ; preds = %143, %79
  %85 = load ptr, ptr %5, align 8
  %86 = getelementptr inbounds %struct.parse_buffer, ptr %85, i32 0, i32 4
  %87 = call ptr @cJSON_New_Item(ptr noundef %86)
  store ptr %87, ptr %8, align 8
  %88 = load ptr, ptr %8, align 8
  %89 = icmp eq ptr %88, null
  br i1 %89, label %90, label %91

90:                                               ; preds = %84
  br label %192

91:                                               ; preds = %84
  %92 = load ptr, ptr %6, align 8
  %93 = icmp eq ptr %92, null
  br i1 %93, label %94, label %96

94:                                               ; preds = %91
  %95 = load ptr, ptr %8, align 8
  store ptr %95, ptr %6, align 8
  store ptr %95, ptr %7, align 8
  br label %104

96:                                               ; preds = %91
  %97 = load ptr, ptr %8, align 8
  %98 = load ptr, ptr %7, align 8
  %99 = getelementptr inbounds %struct.cJSON, ptr %98, i32 0, i32 0
  store ptr %97, ptr %99, align 8
  %100 = load ptr, ptr %7, align 8
  %101 = load ptr, ptr %8, align 8
  %102 = getelementptr inbounds %struct.cJSON, ptr %101, i32 0, i32 1
  store ptr %100, ptr %102, align 8
  %103 = load ptr, ptr %8, align 8
  store ptr %103, ptr %7, align 8
  br label %104

104:                                              ; preds = %96, %94
  %105 = load ptr, ptr %5, align 8
  %106 = getelementptr inbounds %struct.parse_buffer, ptr %105, i32 0, i32 2
  %107 = load i64, ptr %106, align 8
  %108 = add i64 %107, 1
  store i64 %108, ptr %106, align 8
  %109 = load ptr, ptr %5, align 8
  %110 = call ptr @buffer_skip_whitespace(ptr noundef %109)
  %111 = load ptr, ptr %7, align 8
  %112 = load ptr, ptr %5, align 8
  %113 = call i32 @parse_value(ptr noundef %111, ptr noundef %112)
  %114 = icmp ne i32 %113, 0
  br i1 %114, label %116, label %115

115:                                              ; preds = %104
  br label %192

116:                                              ; preds = %104
  %117 = load ptr, ptr %5, align 8
  %118 = call ptr @buffer_skip_whitespace(ptr noundef %117)
  br label %119

119:                                              ; preds = %116
  %120 = load ptr, ptr %5, align 8
  %121 = icmp ne ptr %120, null
  br i1 %121, label %122, label %143

122:                                              ; preds = %119
  %123 = load ptr, ptr %5, align 8
  %124 = getelementptr inbounds %struct.parse_buffer, ptr %123, i32 0, i32 2
  %125 = load i64, ptr %124, align 8
  %126 = add i64 %125, 0
  %127 = load ptr, ptr %5, align 8
  %128 = getelementptr inbounds %struct.parse_buffer, ptr %127, i32 0, i32 1
  %129 = load i64, ptr %128, align 8
  %130 = icmp ult i64 %126, %129
  br i1 %130, label %131, label %143

131:                                              ; preds = %122
  %132 = load ptr, ptr %5, align 8
  %133 = getelementptr inbounds %struct.parse_buffer, ptr %132, i32 0, i32 0
  %134 = load ptr, ptr %133, align 8
  %135 = load ptr, ptr %5, align 8
  %136 = getelementptr inbounds %struct.parse_buffer, ptr %135, i32 0, i32 2
  %137 = load i64, ptr %136, align 8
  %138 = getelementptr inbounds i8, ptr %134, i64 %137
  %139 = getelementptr inbounds i8, ptr %138, i64 0
  %140 = load i8, ptr %139, align 1
  %141 = zext i8 %140 to i32
  %142 = icmp eq i32 %141, 44
  br label %143

143:                                              ; preds = %131, %122, %119
  %144 = phi i1 [ false, %122 ], [ false, %119 ], [ %142, %131 ]
  br i1 %144, label %84, label %145, !llvm.loop !13

145:                                              ; preds = %143
  %146 = load ptr, ptr %5, align 8
  %147 = icmp ne ptr %146, null
  br i1 %147, label %148, label %169

148:                                              ; preds = %145
  %149 = load ptr, ptr %5, align 8
  %150 = getelementptr inbounds %struct.parse_buffer, ptr %149, i32 0, i32 2
  %151 = load i64, ptr %150, align 8
  %152 = add i64 %151, 0
  %153 = load ptr, ptr %5, align 8
  %154 = getelementptr inbounds %struct.parse_buffer, ptr %153, i32 0, i32 1
  %155 = load i64, ptr %154, align 8
  %156 = icmp ult i64 %152, %155
  br i1 %156, label %157, label %169

157:                                              ; preds = %148
  %158 = load ptr, ptr %5, align 8
  %159 = getelementptr inbounds %struct.parse_buffer, ptr %158, i32 0, i32 0
  %160 = load ptr, ptr %159, align 8
  %161 = load ptr, ptr %5, align 8
  %162 = getelementptr inbounds %struct.parse_buffer, ptr %161, i32 0, i32 2
  %163 = load i64, ptr %162, align 8
  %164 = getelementptr inbounds i8, ptr %160, i64 %163
  %165 = getelementptr inbounds i8, ptr %164, i64 0
  %166 = load i8, ptr %165, align 1
  %167 = zext i8 %166 to i32
  %168 = icmp ne i32 %167, 93
  br i1 %168, label %169, label %170

169:                                              ; preds = %157, %148, %145
  br label %192

170:                                              ; preds = %157
  br label %171

171:                                              ; preds = %170, %61
  %172 = load ptr, ptr %5, align 8
  %173 = getelementptr inbounds %struct.parse_buffer, ptr %172, i32 0, i32 3
  %174 = load i64, ptr %173, align 8
  %175 = add i64 %174, -1
  store i64 %175, ptr %173, align 8
  %176 = load ptr, ptr %6, align 8
  %177 = icmp ne ptr %176, null
  br i1 %177, label %178, label %182

178:                                              ; preds = %171
  %179 = load ptr, ptr %7, align 8
  %180 = load ptr, ptr %6, align 8
  %181 = getelementptr inbounds %struct.cJSON, ptr %180, i32 0, i32 1
  store ptr %179, ptr %181, align 8
  br label %182

182:                                              ; preds = %178, %171
  %183 = load ptr, ptr %4, align 8
  %184 = getelementptr inbounds %struct.cJSON, ptr %183, i32 0, i32 3
  store i32 32, ptr %184, align 8
  %185 = load ptr, ptr %6, align 8
  %186 = load ptr, ptr %4, align 8
  %187 = getelementptr inbounds %struct.cJSON, ptr %186, i32 0, i32 2
  store ptr %185, ptr %187, align 8
  %188 = load ptr, ptr %5, align 8
  %189 = getelementptr inbounds %struct.parse_buffer, ptr %188, i32 0, i32 2
  %190 = load i64, ptr %189, align 8
  %191 = add i64 %190, 1
  store i64 %191, ptr %189, align 8
  store i32 1, ptr %3, align 4
  br label %198

192:                                              ; preds = %169, %115, %90, %74, %30
  %193 = load ptr, ptr %6, align 8
  %194 = icmp ne ptr %193, null
  br i1 %194, label %195, label %197

195:                                              ; preds = %192
  %196 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %196)
  br label %197

197:                                              ; preds = %195, %192
  store i32 0, ptr %3, align 4
  br label %198

198:                                              ; preds = %197, %182, %13
  %199 = load i32, ptr %3, align 4
  ret i32 %199
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_object(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store ptr null, ptr %7, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = getelementptr inbounds %struct.parse_buffer, ptr %9, i32 0, i32 3
  %11 = load i64, ptr %10, align 8
  %12 = icmp uge i64 %11, 1000
  br i1 %12, label %13, label %14

13:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %269

14:                                               ; preds = %2
  %15 = load ptr, ptr %5, align 8
  %16 = getelementptr inbounds %struct.parse_buffer, ptr %15, i32 0, i32 3
  %17 = load i64, ptr %16, align 8
  %18 = add i64 %17, 1
  store i64 %18, ptr %16, align 8
  %19 = load ptr, ptr %5, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %42

21:                                               ; preds = %14
  %22 = load ptr, ptr %5, align 8
  %23 = getelementptr inbounds %struct.parse_buffer, ptr %22, i32 0, i32 2
  %24 = load i64, ptr %23, align 8
  %25 = add i64 %24, 0
  %26 = load ptr, ptr %5, align 8
  %27 = getelementptr inbounds %struct.parse_buffer, ptr %26, i32 0, i32 1
  %28 = load i64, ptr %27, align 8
  %29 = icmp ult i64 %25, %28
  br i1 %29, label %30, label %42

30:                                               ; preds = %21
  %31 = load ptr, ptr %5, align 8
  %32 = getelementptr inbounds %struct.parse_buffer, ptr %31, i32 0, i32 0
  %33 = load ptr, ptr %32, align 8
  %34 = load ptr, ptr %5, align 8
  %35 = getelementptr inbounds %struct.parse_buffer, ptr %34, i32 0, i32 2
  %36 = load i64, ptr %35, align 8
  %37 = getelementptr inbounds i8, ptr %33, i64 %36
  %38 = getelementptr inbounds i8, ptr %37, i64 0
  %39 = load i8, ptr %38, align 1
  %40 = zext i8 %39 to i32
  %41 = icmp ne i32 %40, 123
  br i1 %41, label %42, label %43

42:                                               ; preds = %30, %21, %14
  br label %263

43:                                               ; preds = %30
  %44 = load ptr, ptr %5, align 8
  %45 = getelementptr inbounds %struct.parse_buffer, ptr %44, i32 0, i32 2
  %46 = load i64, ptr %45, align 8
  %47 = add i64 %46, 1
  store i64 %47, ptr %45, align 8
  %48 = load ptr, ptr %5, align 8
  %49 = call ptr @buffer_skip_whitespace(ptr noundef %48)
  %50 = load ptr, ptr %5, align 8
  %51 = icmp ne ptr %50, null
  br i1 %51, label %52, label %74

52:                                               ; preds = %43
  %53 = load ptr, ptr %5, align 8
  %54 = getelementptr inbounds %struct.parse_buffer, ptr %53, i32 0, i32 2
  %55 = load i64, ptr %54, align 8
  %56 = add i64 %55, 0
  %57 = load ptr, ptr %5, align 8
  %58 = getelementptr inbounds %struct.parse_buffer, ptr %57, i32 0, i32 1
  %59 = load i64, ptr %58, align 8
  %60 = icmp ult i64 %56, %59
  br i1 %60, label %61, label %74

61:                                               ; preds = %52
  %62 = load ptr, ptr %5, align 8
  %63 = getelementptr inbounds %struct.parse_buffer, ptr %62, i32 0, i32 0
  %64 = load ptr, ptr %63, align 8
  %65 = load ptr, ptr %5, align 8
  %66 = getelementptr inbounds %struct.parse_buffer, ptr %65, i32 0, i32 2
  %67 = load i64, ptr %66, align 8
  %68 = getelementptr inbounds i8, ptr %64, i64 %67
  %69 = getelementptr inbounds i8, ptr %68, i64 0
  %70 = load i8, ptr %69, align 1
  %71 = zext i8 %70 to i32
  %72 = icmp eq i32 %71, 125
  br i1 %72, label %73, label %74

73:                                               ; preds = %61
  br label %242

74:                                               ; preds = %61, %52, %43
  %75 = load ptr, ptr %5, align 8
  %76 = icmp ne ptr %75, null
  br i1 %76, label %77, label %86

77:                                               ; preds = %74
  %78 = load ptr, ptr %5, align 8
  %79 = getelementptr inbounds %struct.parse_buffer, ptr %78, i32 0, i32 2
  %80 = load i64, ptr %79, align 8
  %81 = add i64 %80, 0
  %82 = load ptr, ptr %5, align 8
  %83 = getelementptr inbounds %struct.parse_buffer, ptr %82, i32 0, i32 1
  %84 = load i64, ptr %83, align 8
  %85 = icmp ult i64 %81, %84
  br i1 %85, label %91, label %86

86:                                               ; preds = %77, %74
  %87 = load ptr, ptr %5, align 8
  %88 = getelementptr inbounds %struct.parse_buffer, ptr %87, i32 0, i32 2
  %89 = load i64, ptr %88, align 8
  %90 = add i64 %89, -1
  store i64 %90, ptr %88, align 8
  br label %263

91:                                               ; preds = %77
  %92 = load ptr, ptr %5, align 8
  %93 = getelementptr inbounds %struct.parse_buffer, ptr %92, i32 0, i32 2
  %94 = load i64, ptr %93, align 8
  %95 = add i64 %94, -1
  store i64 %95, ptr %93, align 8
  br label %96

96:                                               ; preds = %214, %91
  %97 = load ptr, ptr %5, align 8
  %98 = getelementptr inbounds %struct.parse_buffer, ptr %97, i32 0, i32 4
  %99 = call ptr @cJSON_New_Item(ptr noundef %98)
  store ptr %99, ptr %8, align 8
  %100 = load ptr, ptr %8, align 8
  %101 = icmp eq ptr %100, null
  br i1 %101, label %102, label %103

102:                                              ; preds = %96
  br label %263

103:                                              ; preds = %96
  %104 = load ptr, ptr %6, align 8
  %105 = icmp eq ptr %104, null
  br i1 %105, label %106, label %108

106:                                              ; preds = %103
  %107 = load ptr, ptr %8, align 8
  store ptr %107, ptr %6, align 8
  store ptr %107, ptr %7, align 8
  br label %116

108:                                              ; preds = %103
  %109 = load ptr, ptr %8, align 8
  %110 = load ptr, ptr %7, align 8
  %111 = getelementptr inbounds %struct.cJSON, ptr %110, i32 0, i32 0
  store ptr %109, ptr %111, align 8
  %112 = load ptr, ptr %7, align 8
  %113 = load ptr, ptr %8, align 8
  %114 = getelementptr inbounds %struct.cJSON, ptr %113, i32 0, i32 1
  store ptr %112, ptr %114, align 8
  %115 = load ptr, ptr %8, align 8
  store ptr %115, ptr %7, align 8
  br label %116

116:                                              ; preds = %108, %106
  %117 = load ptr, ptr %5, align 8
  %118 = icmp ne ptr %117, null
  br i1 %118, label %119, label %128

119:                                              ; preds = %116
  %120 = load ptr, ptr %5, align 8
  %121 = getelementptr inbounds %struct.parse_buffer, ptr %120, i32 0, i32 2
  %122 = load i64, ptr %121, align 8
  %123 = add i64 %122, 1
  %124 = load ptr, ptr %5, align 8
  %125 = getelementptr inbounds %struct.parse_buffer, ptr %124, i32 0, i32 1
  %126 = load i64, ptr %125, align 8
  %127 = icmp ult i64 %123, %126
  br i1 %127, label %129, label %128

128:                                              ; preds = %119, %116
  br label %263

129:                                              ; preds = %119
  %130 = load ptr, ptr %5, align 8
  %131 = getelementptr inbounds %struct.parse_buffer, ptr %130, i32 0, i32 2
  %132 = load i64, ptr %131, align 8
  %133 = add i64 %132, 1
  store i64 %133, ptr %131, align 8
  %134 = load ptr, ptr %5, align 8
  %135 = call ptr @buffer_skip_whitespace(ptr noundef %134)
  %136 = load ptr, ptr %7, align 8
  %137 = load ptr, ptr %5, align 8
  %138 = call i32 @parse_string(ptr noundef %136, ptr noundef %137)
  %139 = icmp ne i32 %138, 0
  br i1 %139, label %141, label %140

140:                                              ; preds = %129
  br label %263

141:                                              ; preds = %129
  %142 = load ptr, ptr %5, align 8
  %143 = call ptr @buffer_skip_whitespace(ptr noundef %142)
  %144 = load ptr, ptr %7, align 8
  %145 = getelementptr inbounds %struct.cJSON, ptr %144, i32 0, i32 4
  %146 = load ptr, ptr %145, align 8
  %147 = load ptr, ptr %7, align 8
  %148 = getelementptr inbounds %struct.cJSON, ptr %147, i32 0, i32 7
  store ptr %146, ptr %148, align 8
  %149 = load ptr, ptr %7, align 8
  %150 = getelementptr inbounds %struct.cJSON, ptr %149, i32 0, i32 4
  store ptr null, ptr %150, align 8
  %151 = load ptr, ptr %5, align 8
  %152 = icmp ne ptr %151, null
  br i1 %152, label %153, label %174

153:                                              ; preds = %141
  %154 = load ptr, ptr %5, align 8
  %155 = getelementptr inbounds %struct.parse_buffer, ptr %154, i32 0, i32 2
  %156 = load i64, ptr %155, align 8
  %157 = add i64 %156, 0
  %158 = load ptr, ptr %5, align 8
  %159 = getelementptr inbounds %struct.parse_buffer, ptr %158, i32 0, i32 1
  %160 = load i64, ptr %159, align 8
  %161 = icmp ult i64 %157, %160
  br i1 %161, label %162, label %174

162:                                              ; preds = %153
  %163 = load ptr, ptr %5, align 8
  %164 = getelementptr inbounds %struct.parse_buffer, ptr %163, i32 0, i32 0
  %165 = load ptr, ptr %164, align 8
  %166 = load ptr, ptr %5, align 8
  %167 = getelementptr inbounds %struct.parse_buffer, ptr %166, i32 0, i32 2
  %168 = load i64, ptr %167, align 8
  %169 = getelementptr inbounds i8, ptr %165, i64 %168
  %170 = getelementptr inbounds i8, ptr %169, i64 0
  %171 = load i8, ptr %170, align 1
  %172 = zext i8 %171 to i32
  %173 = icmp ne i32 %172, 58
  br i1 %173, label %174, label %175

174:                                              ; preds = %162, %153, %141
  br label %263

175:                                              ; preds = %162
  %176 = load ptr, ptr %5, align 8
  %177 = getelementptr inbounds %struct.parse_buffer, ptr %176, i32 0, i32 2
  %178 = load i64, ptr %177, align 8
  %179 = add i64 %178, 1
  store i64 %179, ptr %177, align 8
  %180 = load ptr, ptr %5, align 8
  %181 = call ptr @buffer_skip_whitespace(ptr noundef %180)
  %182 = load ptr, ptr %7, align 8
  %183 = load ptr, ptr %5, align 8
  %184 = call i32 @parse_value(ptr noundef %182, ptr noundef %183)
  %185 = icmp ne i32 %184, 0
  br i1 %185, label %187, label %186

186:                                              ; preds = %175
  br label %263

187:                                              ; preds = %175
  %188 = load ptr, ptr %5, align 8
  %189 = call ptr @buffer_skip_whitespace(ptr noundef %188)
  br label %190

190:                                              ; preds = %187
  %191 = load ptr, ptr %5, align 8
  %192 = icmp ne ptr %191, null
  br i1 %192, label %193, label %214

193:                                              ; preds = %190
  %194 = load ptr, ptr %5, align 8
  %195 = getelementptr inbounds %struct.parse_buffer, ptr %194, i32 0, i32 2
  %196 = load i64, ptr %195, align 8
  %197 = add i64 %196, 0
  %198 = load ptr, ptr %5, align 8
  %199 = getelementptr inbounds %struct.parse_buffer, ptr %198, i32 0, i32 1
  %200 = load i64, ptr %199, align 8
  %201 = icmp ult i64 %197, %200
  br i1 %201, label %202, label %214

202:                                              ; preds = %193
  %203 = load ptr, ptr %5, align 8
  %204 = getelementptr inbounds %struct.parse_buffer, ptr %203, i32 0, i32 0
  %205 = load ptr, ptr %204, align 8
  %206 = load ptr, ptr %5, align 8
  %207 = getelementptr inbounds %struct.parse_buffer, ptr %206, i32 0, i32 2
  %208 = load i64, ptr %207, align 8
  %209 = getelementptr inbounds i8, ptr %205, i64 %208
  %210 = getelementptr inbounds i8, ptr %209, i64 0
  %211 = load i8, ptr %210, align 1
  %212 = zext i8 %211 to i32
  %213 = icmp eq i32 %212, 44
  br label %214

214:                                              ; preds = %202, %193, %190
  %215 = phi i1 [ false, %193 ], [ false, %190 ], [ %213, %202 ]
  br i1 %215, label %96, label %216, !llvm.loop !14

216:                                              ; preds = %214
  %217 = load ptr, ptr %5, align 8
  %218 = icmp ne ptr %217, null
  br i1 %218, label %219, label %240

219:                                              ; preds = %216
  %220 = load ptr, ptr %5, align 8
  %221 = getelementptr inbounds %struct.parse_buffer, ptr %220, i32 0, i32 2
  %222 = load i64, ptr %221, align 8
  %223 = add i64 %222, 0
  %224 = load ptr, ptr %5, align 8
  %225 = getelementptr inbounds %struct.parse_buffer, ptr %224, i32 0, i32 1
  %226 = load i64, ptr %225, align 8
  %227 = icmp ult i64 %223, %226
  br i1 %227, label %228, label %240

228:                                              ; preds = %219
  %229 = load ptr, ptr %5, align 8
  %230 = getelementptr inbounds %struct.parse_buffer, ptr %229, i32 0, i32 0
  %231 = load ptr, ptr %230, align 8
  %232 = load ptr, ptr %5, align 8
  %233 = getelementptr inbounds %struct.parse_buffer, ptr %232, i32 0, i32 2
  %234 = load i64, ptr %233, align 8
  %235 = getelementptr inbounds i8, ptr %231, i64 %234
  %236 = getelementptr inbounds i8, ptr %235, i64 0
  %237 = load i8, ptr %236, align 1
  %238 = zext i8 %237 to i32
  %239 = icmp ne i32 %238, 125
  br i1 %239, label %240, label %241

240:                                              ; preds = %228, %219, %216
  br label %263

241:                                              ; preds = %228
  br label %242

242:                                              ; preds = %241, %73
  %243 = load ptr, ptr %5, align 8
  %244 = getelementptr inbounds %struct.parse_buffer, ptr %243, i32 0, i32 3
  %245 = load i64, ptr %244, align 8
  %246 = add i64 %245, -1
  store i64 %246, ptr %244, align 8
  %247 = load ptr, ptr %6, align 8
  %248 = icmp ne ptr %247, null
  br i1 %248, label %249, label %253

249:                                              ; preds = %242
  %250 = load ptr, ptr %7, align 8
  %251 = load ptr, ptr %6, align 8
  %252 = getelementptr inbounds %struct.cJSON, ptr %251, i32 0, i32 1
  store ptr %250, ptr %252, align 8
  br label %253

253:                                              ; preds = %249, %242
  %254 = load ptr, ptr %4, align 8
  %255 = getelementptr inbounds %struct.cJSON, ptr %254, i32 0, i32 3
  store i32 64, ptr %255, align 8
  %256 = load ptr, ptr %6, align 8
  %257 = load ptr, ptr %4, align 8
  %258 = getelementptr inbounds %struct.cJSON, ptr %257, i32 0, i32 2
  store ptr %256, ptr %258, align 8
  %259 = load ptr, ptr %5, align 8
  %260 = getelementptr inbounds %struct.parse_buffer, ptr %259, i32 0, i32 2
  %261 = load i64, ptr %260, align 8
  %262 = add i64 %261, 1
  store i64 %262, ptr %260, align 8
  store i32 1, ptr %3, align 4
  br label %269

263:                                              ; preds = %240, %186, %174, %140, %128, %102, %86, %42
  %264 = load ptr, ptr %6, align 8
  %265 = icmp ne ptr %264, null
  br i1 %265, label %266, label %268

266:                                              ; preds = %263
  %267 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %267)
  br label %268

268:                                              ; preds = %266, %263
  store i32 0, ptr %3, align 4
  br label %269

269:                                              ; preds = %268, %253, %13
  %270 = load i32, ptr %3, align 4
  ret i32 %270
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i8 @get_decimal_point() #0 {
  ret i8 46
}

; Function Attrs: nounwind
declare double @strtod(ptr noundef, ptr noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define internal i8 @utf16_literal_to_utf8(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca i8, align 1
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca i64, align 8
  %9 = alloca i32, align 4
  %10 = alloca ptr, align 8
  %11 = alloca i8, align 1
  %12 = alloca i8, align 1
  %13 = alloca i8, align 1
  %14 = alloca i8, align 1
  %15 = alloca ptr, align 8
  %16 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  store i64 0, ptr %8, align 8
  store i32 0, ptr %9, align 4
  %17 = load ptr, ptr %5, align 8
  store ptr %17, ptr %10, align 8
  store i8 0, ptr %11, align 1
  store i8 0, ptr %12, align 1
  store i8 0, ptr %13, align 1
  store i8 0, ptr %14, align 1
  %18 = load ptr, ptr %6, align 8
  %19 = load ptr, ptr %10, align 8
  %20 = ptrtoint ptr %18 to i64
  %21 = ptrtoint ptr %19 to i64
  %22 = sub i64 %20, %21
  %23 = icmp slt i64 %22, 6
  br i1 %23, label %24, label %25

24:                                               ; preds = %3
  br label %159

25:                                               ; preds = %3
  %26 = load ptr, ptr %10, align 8
  %27 = getelementptr inbounds i8, ptr %26, i64 2
  %28 = call i32 @parse_hex4(ptr noundef %27)
  store i32 %28, ptr %9, align 4
  %29 = load i32, ptr %9, align 4
  %30 = icmp uge i32 %29, 56320
  br i1 %30, label %31, label %35

31:                                               ; preds = %25
  %32 = load i32, ptr %9, align 4
  %33 = icmp ule i32 %32, 57343
  br i1 %33, label %34, label %35

34:                                               ; preds = %31
  br label %159

35:                                               ; preds = %31, %25
  %36 = load i32, ptr %9, align 4
  %37 = icmp uge i32 %36, 55296
  br i1 %37, label %38, label %83

38:                                               ; preds = %35
  %39 = load i32, ptr %9, align 4
  %40 = icmp ule i32 %39, 56319
  br i1 %40, label %41, label %83

41:                                               ; preds = %38
  %42 = load ptr, ptr %10, align 8
  %43 = getelementptr inbounds i8, ptr %42, i64 6
  store ptr %43, ptr %15, align 8
  store i32 0, ptr %16, align 4
  store i8 12, ptr %13, align 1
  %44 = load ptr, ptr %6, align 8
  %45 = load ptr, ptr %15, align 8
  %46 = ptrtoint ptr %44 to i64
  %47 = ptrtoint ptr %45 to i64
  %48 = sub i64 %46, %47
  %49 = icmp slt i64 %48, 6
  br i1 %49, label %50, label %51

50:                                               ; preds = %41
  br label %159

51:                                               ; preds = %41
  %52 = load ptr, ptr %15, align 8
  %53 = getelementptr inbounds i8, ptr %52, i64 0
  %54 = load i8, ptr %53, align 1
  %55 = zext i8 %54 to i32
  %56 = icmp ne i32 %55, 92
  br i1 %56, label %63, label %57

57:                                               ; preds = %51
  %58 = load ptr, ptr %15, align 8
  %59 = getelementptr inbounds i8, ptr %58, i64 1
  %60 = load i8, ptr %59, align 1
  %61 = zext i8 %60 to i32
  %62 = icmp ne i32 %61, 117
  br i1 %62, label %63, label %64

63:                                               ; preds = %57, %51
  br label %159

64:                                               ; preds = %57
  %65 = load ptr, ptr %15, align 8
  %66 = getelementptr inbounds i8, ptr %65, i64 2
  %67 = call i32 @parse_hex4(ptr noundef %66)
  store i32 %67, ptr %16, align 4
  %68 = load i32, ptr %16, align 4
  %69 = icmp ult i32 %68, 56320
  br i1 %69, label %73, label %70

70:                                               ; preds = %64
  %71 = load i32, ptr %16, align 4
  %72 = icmp ugt i32 %71, 57343
  br i1 %72, label %73, label %74

73:                                               ; preds = %70, %64
  br label %159

74:                                               ; preds = %70
  %75 = load i32, ptr %9, align 4
  %76 = and i32 %75, 1023
  %77 = shl i32 %76, 10
  %78 = load i32, ptr %16, align 4
  %79 = and i32 %78, 1023
  %80 = or i32 %77, %79
  %81 = add i32 65536, %80
  %82 = zext i32 %81 to i64
  store i64 %82, ptr %8, align 8
  br label %86

83:                                               ; preds = %38, %35
  store i8 6, ptr %13, align 1
  %84 = load i32, ptr %9, align 4
  %85 = zext i32 %84 to i64
  store i64 %85, ptr %8, align 8
  br label %86

86:                                               ; preds = %83, %74
  %87 = load i64, ptr %8, align 8
  %88 = icmp ult i64 %87, 128
  br i1 %88, label %89, label %90

89:                                               ; preds = %86
  store i8 1, ptr %11, align 1
  br label %106

90:                                               ; preds = %86
  %91 = load i64, ptr %8, align 8
  %92 = icmp ult i64 %91, 2048
  br i1 %92, label %93, label %94

93:                                               ; preds = %90
  store i8 2, ptr %11, align 1
  store i8 -64, ptr %14, align 1
  br label %105

94:                                               ; preds = %90
  %95 = load i64, ptr %8, align 8
  %96 = icmp ult i64 %95, 65536
  br i1 %96, label %97, label %98

97:                                               ; preds = %94
  store i8 3, ptr %11, align 1
  store i8 -32, ptr %14, align 1
  br label %104

98:                                               ; preds = %94
  %99 = load i64, ptr %8, align 8
  %100 = icmp ule i64 %99, 1114111
  br i1 %100, label %101, label %102

101:                                              ; preds = %98
  store i8 4, ptr %11, align 1
  store i8 -16, ptr %14, align 1
  br label %103

102:                                              ; preds = %98
  br label %159

103:                                              ; preds = %101
  br label %104

104:                                              ; preds = %103, %97
  br label %105

105:                                              ; preds = %104, %93
  br label %106

106:                                              ; preds = %105, %89
  %107 = load i8, ptr %11, align 1
  %108 = zext i8 %107 to i32
  %109 = sub nsw i32 %108, 1
  %110 = trunc i32 %109 to i8
  store i8 %110, ptr %12, align 1
  br label %111

111:                                              ; preds = %127, %106
  %112 = load i8, ptr %12, align 1
  %113 = zext i8 %112 to i32
  %114 = icmp sgt i32 %113, 0
  br i1 %114, label %115, label %130

115:                                              ; preds = %111
  %116 = load i64, ptr %8, align 8
  %117 = or i64 %116, 128
  %118 = and i64 %117, 191
  %119 = trunc i64 %118 to i8
  %120 = load ptr, ptr %7, align 8
  %121 = load ptr, ptr %120, align 8
  %122 = load i8, ptr %12, align 1
  %123 = zext i8 %122 to i64
  %124 = getelementptr inbounds i8, ptr %121, i64 %123
  store i8 %119, ptr %124, align 1
  %125 = load i64, ptr %8, align 8
  %126 = lshr i64 %125, 6
  store i64 %126, ptr %8, align 8
  br label %127

127:                                              ; preds = %115
  %128 = load i8, ptr %12, align 1
  %129 = add i8 %128, -1
  store i8 %129, ptr %12, align 1
  br label %111, !llvm.loop !15

130:                                              ; preds = %111
  %131 = load i8, ptr %11, align 1
  %132 = zext i8 %131 to i32
  %133 = icmp sgt i32 %132, 1
  br i1 %133, label %134, label %144

134:                                              ; preds = %130
  %135 = load i64, ptr %8, align 8
  %136 = load i8, ptr %14, align 1
  %137 = zext i8 %136 to i64
  %138 = or i64 %135, %137
  %139 = and i64 %138, 255
  %140 = trunc i64 %139 to i8
  %141 = load ptr, ptr %7, align 8
  %142 = load ptr, ptr %141, align 8
  %143 = getelementptr inbounds i8, ptr %142, i64 0
  store i8 %140, ptr %143, align 1
  br label %151

144:                                              ; preds = %130
  %145 = load i64, ptr %8, align 8
  %146 = and i64 %145, 127
  %147 = trunc i64 %146 to i8
  %148 = load ptr, ptr %7, align 8
  %149 = load ptr, ptr %148, align 8
  %150 = getelementptr inbounds i8, ptr %149, i64 0
  store i8 %147, ptr %150, align 1
  br label %151

151:                                              ; preds = %144, %134
  %152 = load i8, ptr %11, align 1
  %153 = zext i8 %152 to i32
  %154 = load ptr, ptr %7, align 8
  %155 = load ptr, ptr %154, align 8
  %156 = sext i32 %153 to i64
  %157 = getelementptr inbounds i8, ptr %155, i64 %156
  store ptr %157, ptr %154, align 8
  %158 = load i8, ptr %13, align 1
  store i8 %158, ptr %4, align 1
  br label %160

159:                                              ; preds = %102, %73, %63, %50, %34, %24
  store i8 0, ptr %4, align 1
  br label %160

160:                                              ; preds = %159, %151
  %161 = load i8, ptr %4, align 1
  ret i8 %161
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @parse_hex4(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca i64, align 8
  store ptr %0, ptr %3, align 8
  store i32 0, ptr %4, align 4
  store i64 0, ptr %5, align 8
  store i64 0, ptr %5, align 8
  br label %6

6:                                                ; preds = %90, %1
  %7 = load i64, ptr %5, align 8
  %8 = icmp ult i64 %7, 4
  br i1 %8, label %9, label %93

9:                                                ; preds = %6
  %10 = load ptr, ptr %3, align 8
  %11 = load i64, ptr %5, align 8
  %12 = getelementptr inbounds i8, ptr %10, i64 %11
  %13 = load i8, ptr %12, align 1
  %14 = zext i8 %13 to i32
  %15 = icmp sge i32 %14, 48
  br i1 %15, label %16, label %32

16:                                               ; preds = %9
  %17 = load ptr, ptr %3, align 8
  %18 = load i64, ptr %5, align 8
  %19 = getelementptr inbounds i8, ptr %17, i64 %18
  %20 = load i8, ptr %19, align 1
  %21 = zext i8 %20 to i32
  %22 = icmp sle i32 %21, 57
  br i1 %22, label %23, label %32

23:                                               ; preds = %16
  %24 = load ptr, ptr %3, align 8
  %25 = load i64, ptr %5, align 8
  %26 = getelementptr inbounds i8, ptr %24, i64 %25
  %27 = load i8, ptr %26, align 1
  %28 = zext i8 %27 to i32
  %29 = sub i32 %28, 48
  %30 = load i32, ptr %4, align 4
  %31 = add i32 %30, %29
  store i32 %31, ptr %4, align 4
  br label %83

32:                                               ; preds = %16, %9
  %33 = load ptr, ptr %3, align 8
  %34 = load i64, ptr %5, align 8
  %35 = getelementptr inbounds i8, ptr %33, i64 %34
  %36 = load i8, ptr %35, align 1
  %37 = zext i8 %36 to i32
  %38 = icmp sge i32 %37, 65
  br i1 %38, label %39, label %56

39:                                               ; preds = %32
  %40 = load ptr, ptr %3, align 8
  %41 = load i64, ptr %5, align 8
  %42 = getelementptr inbounds i8, ptr %40, i64 %41
  %43 = load i8, ptr %42, align 1
  %44 = zext i8 %43 to i32
  %45 = icmp sle i32 %44, 70
  br i1 %45, label %46, label %56

46:                                               ; preds = %39
  %47 = load ptr, ptr %3, align 8
  %48 = load i64, ptr %5, align 8
  %49 = getelementptr inbounds i8, ptr %47, i64 %48
  %50 = load i8, ptr %49, align 1
  %51 = zext i8 %50 to i32
  %52 = add i32 10, %51
  %53 = sub i32 %52, 65
  %54 = load i32, ptr %4, align 4
  %55 = add i32 %54, %53
  store i32 %55, ptr %4, align 4
  br label %82

56:                                               ; preds = %39, %32
  %57 = load ptr, ptr %3, align 8
  %58 = load i64, ptr %5, align 8
  %59 = getelementptr inbounds i8, ptr %57, i64 %58
  %60 = load i8, ptr %59, align 1
  %61 = zext i8 %60 to i32
  %62 = icmp sge i32 %61, 97
  br i1 %62, label %63, label %80

63:                                               ; preds = %56
  %64 = load ptr, ptr %3, align 8
  %65 = load i64, ptr %5, align 8
  %66 = getelementptr inbounds i8, ptr %64, i64 %65
  %67 = load i8, ptr %66, align 1
  %68 = zext i8 %67 to i32
  %69 = icmp sle i32 %68, 102
  br i1 %69, label %70, label %80

70:                                               ; preds = %63
  %71 = load ptr, ptr %3, align 8
  %72 = load i64, ptr %5, align 8
  %73 = getelementptr inbounds i8, ptr %71, i64 %72
  %74 = load i8, ptr %73, align 1
  %75 = zext i8 %74 to i32
  %76 = add i32 10, %75
  %77 = sub i32 %76, 97
  %78 = load i32, ptr %4, align 4
  %79 = add i32 %78, %77
  store i32 %79, ptr %4, align 4
  br label %81

80:                                               ; preds = %63, %56
  store i32 0, ptr %2, align 4
  br label %95

81:                                               ; preds = %70
  br label %82

82:                                               ; preds = %81, %46
  br label %83

83:                                               ; preds = %82, %23
  %84 = load i64, ptr %5, align 8
  %85 = icmp ult i64 %84, 3
  br i1 %85, label %86, label %89

86:                                               ; preds = %83
  %87 = load i32, ptr %4, align 4
  %88 = shl i32 %87, 4
  store i32 %88, ptr %4, align 4
  br label %89

89:                                               ; preds = %86, %83
  br label %90

90:                                               ; preds = %89
  %91 = load i64, ptr %5, align 8
  %92 = add i64 %91, 1
  store i64 %92, ptr %5, align 8
  br label %6, !llvm.loop !16

93:                                               ; preds = %6
  %94 = load i32, ptr %4, align 4
  store i32 %94, ptr %2, align 4
  br label %95

95:                                               ; preds = %93, %80
  %96 = load i32, ptr %2, align 4
  ret i32 %96
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_Parse(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = call ptr @cJSON_ParseWithOpts(ptr noundef %3, ptr noundef null, i32 noundef 0)
  ret ptr %4
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_ParseWithLength(ptr noundef %0, i64 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i64, align 8
  store ptr %0, ptr %3, align 8
  store i64 %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load i64, ptr %4, align 8
  %7 = call ptr @cJSON_ParseWithLengthOpts(ptr noundef %5, i64 noundef %6, ptr noundef null, i32 noundef 0)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_Print(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = call ptr @print(ptr noundef %3, i32 noundef 1, ptr noundef @global_hooks)
  ret ptr %4
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @print(ptr noundef %0, i32 noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca [1 x %struct.printbuffer], align 8
  %9 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store i32 %1, ptr %6, align 4
  store ptr %2, ptr %7, align 8
  store ptr null, ptr %9, align 8
  %10 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  call void @llvm.memset.p0.i64(ptr align 8 %10, i8 0, i64 64, i1 false)
  %11 = load ptr, ptr %7, align 8
  %12 = getelementptr inbounds %struct.internal_hooks, ptr %11, i32 0, i32 0
  %13 = load ptr, ptr %12, align 8
  %14 = call ptr %13(i64 noundef 256)
  %15 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %16 = getelementptr inbounds %struct.printbuffer, ptr %15, i32 0, i32 0
  store ptr %14, ptr %16, align 8
  %17 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %18 = getelementptr inbounds %struct.printbuffer, ptr %17, i32 0, i32 1
  store i64 256, ptr %18, align 8
  %19 = load i32, ptr %6, align 4
  %20 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %21 = getelementptr inbounds %struct.printbuffer, ptr %20, i32 0, i32 5
  store i32 %19, ptr %21, align 4
  %22 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %23 = getelementptr inbounds %struct.printbuffer, ptr %22, i32 0, i32 6
  %24 = load ptr, ptr %7, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %23, ptr align 8 %24, i64 24, i1 false)
  %25 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %26 = getelementptr inbounds %struct.printbuffer, ptr %25, i32 0, i32 0
  %27 = load ptr, ptr %26, align 8
  %28 = icmp eq ptr %27, null
  br i1 %28, label %29, label %30

29:                                               ; preds = %3
  br label %111

30:                                               ; preds = %3
  %31 = load ptr, ptr %5, align 8
  %32 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %33 = call i32 @print_value(ptr noundef %31, ptr noundef %32)
  %34 = icmp ne i32 %33, 0
  br i1 %34, label %36, label %35

35:                                               ; preds = %30
  br label %111

36:                                               ; preds = %30
  %37 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  call void @update_offset(ptr noundef %37)
  %38 = load ptr, ptr %7, align 8
  %39 = getelementptr inbounds %struct.internal_hooks, ptr %38, i32 0, i32 2
  %40 = load ptr, ptr %39, align 8
  %41 = icmp ne ptr %40, null
  br i1 %41, label %42, label %60

42:                                               ; preds = %36
  %43 = load ptr, ptr %7, align 8
  %44 = getelementptr inbounds %struct.internal_hooks, ptr %43, i32 0, i32 2
  %45 = load ptr, ptr %44, align 8
  %46 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %47 = getelementptr inbounds %struct.printbuffer, ptr %46, i32 0, i32 0
  %48 = load ptr, ptr %47, align 8
  %49 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %50 = getelementptr inbounds %struct.printbuffer, ptr %49, i32 0, i32 2
  %51 = load i64, ptr %50, align 8
  %52 = add i64 %51, 1
  %53 = call ptr %45(ptr noundef %48, i64 noundef %52)
  store ptr %53, ptr %9, align 8
  %54 = load ptr, ptr %9, align 8
  %55 = icmp eq ptr %54, null
  br i1 %55, label %56, label %57

56:                                               ; preds = %42
  br label %111

57:                                               ; preds = %42
  %58 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %59 = getelementptr inbounds %struct.printbuffer, ptr %58, i32 0, i32 0
  store ptr null, ptr %59, align 8
  br label %109

60:                                               ; preds = %36
  %61 = load ptr, ptr %7, align 8
  %62 = getelementptr inbounds %struct.internal_hooks, ptr %61, i32 0, i32 0
  %63 = load ptr, ptr %62, align 8
  %64 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %65 = getelementptr inbounds %struct.printbuffer, ptr %64, i32 0, i32 2
  %66 = load i64, ptr %65, align 8
  %67 = add i64 %66, 1
  %68 = call ptr %63(i64 noundef %67)
  store ptr %68, ptr %9, align 8
  %69 = load ptr, ptr %9, align 8
  %70 = icmp eq ptr %69, null
  br i1 %70, label %71, label %72

71:                                               ; preds = %60
  br label %111

72:                                               ; preds = %60
  %73 = load ptr, ptr %9, align 8
  %74 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %75 = getelementptr inbounds %struct.printbuffer, ptr %74, i32 0, i32 0
  %76 = load ptr, ptr %75, align 8
  %77 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %78 = getelementptr inbounds %struct.printbuffer, ptr %77, i32 0, i32 1
  %79 = load i64, ptr %78, align 8
  %80 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %81 = getelementptr inbounds %struct.printbuffer, ptr %80, i32 0, i32 2
  %82 = load i64, ptr %81, align 8
  %83 = add i64 %82, 1
  %84 = icmp ult i64 %79, %83
  br i1 %84, label %85, label %89

85:                                               ; preds = %72
  %86 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %87 = getelementptr inbounds %struct.printbuffer, ptr %86, i32 0, i32 1
  %88 = load i64, ptr %87, align 8
  br label %94

89:                                               ; preds = %72
  %90 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %91 = getelementptr inbounds %struct.printbuffer, ptr %90, i32 0, i32 2
  %92 = load i64, ptr %91, align 8
  %93 = add i64 %92, 1
  br label %94

94:                                               ; preds = %89, %85
  %95 = phi i64 [ %88, %85 ], [ %93, %89 ]
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %73, ptr align 1 %76, i64 %95, i1 false)
  %96 = load ptr, ptr %9, align 8
  %97 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %98 = getelementptr inbounds %struct.printbuffer, ptr %97, i32 0, i32 2
  %99 = load i64, ptr %98, align 8
  %100 = getelementptr inbounds i8, ptr %96, i64 %99
  store i8 0, ptr %100, align 1
  %101 = load ptr, ptr %7, align 8
  %102 = getelementptr inbounds %struct.internal_hooks, ptr %101, i32 0, i32 1
  %103 = load ptr, ptr %102, align 8
  %104 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %105 = getelementptr inbounds %struct.printbuffer, ptr %104, i32 0, i32 0
  %106 = load ptr, ptr %105, align 8
  call void %103(ptr noundef %106)
  %107 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %108 = getelementptr inbounds %struct.printbuffer, ptr %107, i32 0, i32 0
  store ptr null, ptr %108, align 8
  br label %109

109:                                              ; preds = %94, %57
  %110 = load ptr, ptr %9, align 8
  store ptr %110, ptr %4, align 8
  br label %134

111:                                              ; preds = %71, %56, %35, %29
  %112 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %113 = getelementptr inbounds %struct.printbuffer, ptr %112, i32 0, i32 0
  %114 = load ptr, ptr %113, align 8
  %115 = icmp ne ptr %114, null
  br i1 %115, label %116, label %125

116:                                              ; preds = %111
  %117 = load ptr, ptr %7, align 8
  %118 = getelementptr inbounds %struct.internal_hooks, ptr %117, i32 0, i32 1
  %119 = load ptr, ptr %118, align 8
  %120 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %121 = getelementptr inbounds %struct.printbuffer, ptr %120, i32 0, i32 0
  %122 = load ptr, ptr %121, align 8
  call void %119(ptr noundef %122)
  %123 = getelementptr inbounds [1 x %struct.printbuffer], ptr %8, i64 0, i64 0
  %124 = getelementptr inbounds %struct.printbuffer, ptr %123, i32 0, i32 0
  store ptr null, ptr %124, align 8
  br label %125

125:                                              ; preds = %116, %111
  %126 = load ptr, ptr %9, align 8
  %127 = icmp ne ptr %126, null
  br i1 %127, label %128, label %133

128:                                              ; preds = %125
  %129 = load ptr, ptr %7, align 8
  %130 = getelementptr inbounds %struct.internal_hooks, ptr %129, i32 0, i32 1
  %131 = load ptr, ptr %130, align 8
  %132 = load ptr, ptr %9, align 8
  call void %131(ptr noundef %132)
  store ptr null, ptr %9, align 8
  br label %133

133:                                              ; preds = %128, %125
  store ptr null, ptr %4, align 8
  br label %134

134:                                              ; preds = %133, %109
  %135 = load ptr, ptr %4, align 8
  ret ptr %135
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_value(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %13, label %10

10:                                               ; preds = %2
  %11 = load ptr, ptr %5, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %10, %2
  store i32 0, ptr %3, align 4
  br label %87

14:                                               ; preds = %10
  %15 = load ptr, ptr %4, align 8
  %16 = getelementptr inbounds %struct.cJSON, ptr %15, i32 0, i32 3
  %17 = load i32, ptr %16, align 8
  %18 = and i32 %17, 255
  switch i32 %18, label %86 [
    i32 4, label %19
    i32 1, label %28
    i32 2, label %37
    i32 8, label %46
    i32 128, label %50
    i32 16, label %74
    i32 32, label %78
    i32 64, label %82
  ]

19:                                               ; preds = %14
  %20 = load ptr, ptr %5, align 8
  %21 = call ptr @ensure(ptr noundef %20, i64 noundef 5)
  store ptr %21, ptr %6, align 8
  %22 = load ptr, ptr %6, align 8
  %23 = icmp eq ptr %22, null
  br i1 %23, label %24, label %25

24:                                               ; preds = %19
  store i32 0, ptr %3, align 4
  br label %87

25:                                               ; preds = %19
  %26 = load ptr, ptr %6, align 8
  %27 = call ptr @strcpy(ptr noundef %26, ptr noundef @.str.2) #8
  store i32 1, ptr %3, align 4
  br label %87

28:                                               ; preds = %14
  %29 = load ptr, ptr %5, align 8
  %30 = call ptr @ensure(ptr noundef %29, i64 noundef 6)
  store ptr %30, ptr %6, align 8
  %31 = load ptr, ptr %6, align 8
  %32 = icmp eq ptr %31, null
  br i1 %32, label %33, label %34

33:                                               ; preds = %28
  store i32 0, ptr %3, align 4
  br label %87

34:                                               ; preds = %28
  %35 = load ptr, ptr %6, align 8
  %36 = call ptr @strcpy(ptr noundef %35, ptr noundef @.str.3) #8
  store i32 1, ptr %3, align 4
  br label %87

37:                                               ; preds = %14
  %38 = load ptr, ptr %5, align 8
  %39 = call ptr @ensure(ptr noundef %38, i64 noundef 5)
  store ptr %39, ptr %6, align 8
  %40 = load ptr, ptr %6, align 8
  %41 = icmp eq ptr %40, null
  br i1 %41, label %42, label %43

42:                                               ; preds = %37
  store i32 0, ptr %3, align 4
  br label %87

43:                                               ; preds = %37
  %44 = load ptr, ptr %6, align 8
  %45 = call ptr @strcpy(ptr noundef %44, ptr noundef @.str.4) #8
  store i32 1, ptr %3, align 4
  br label %87

46:                                               ; preds = %14
  %47 = load ptr, ptr %4, align 8
  %48 = load ptr, ptr %5, align 8
  %49 = call i32 @print_number(ptr noundef %47, ptr noundef %48)
  store i32 %49, ptr %3, align 4
  br label %87

50:                                               ; preds = %14
  store i64 0, ptr %7, align 8
  %51 = load ptr, ptr %4, align 8
  %52 = getelementptr inbounds %struct.cJSON, ptr %51, i32 0, i32 4
  %53 = load ptr, ptr %52, align 8
  %54 = icmp eq ptr %53, null
  br i1 %54, label %55, label %56

55:                                               ; preds = %50
  store i32 0, ptr %3, align 4
  br label %87

56:                                               ; preds = %50
  %57 = load ptr, ptr %4, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 4
  %59 = load ptr, ptr %58, align 8
  %60 = call i64 @strlen(ptr noundef %59) #9
  %61 = add i64 %60, 1
  store i64 %61, ptr %7, align 8
  %62 = load ptr, ptr %5, align 8
  %63 = load i64, ptr %7, align 8
  %64 = call ptr @ensure(ptr noundef %62, i64 noundef %63)
  store ptr %64, ptr %6, align 8
  %65 = load ptr, ptr %6, align 8
  %66 = icmp eq ptr %65, null
  br i1 %66, label %67, label %68

67:                                               ; preds = %56
  store i32 0, ptr %3, align 4
  br label %87

68:                                               ; preds = %56
  %69 = load ptr, ptr %6, align 8
  %70 = load ptr, ptr %4, align 8
  %71 = getelementptr inbounds %struct.cJSON, ptr %70, i32 0, i32 4
  %72 = load ptr, ptr %71, align 8
  %73 = load i64, ptr %7, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %69, ptr align 1 %72, i64 %73, i1 false)
  store i32 1, ptr %3, align 4
  br label %87

74:                                               ; preds = %14
  %75 = load ptr, ptr %4, align 8
  %76 = load ptr, ptr %5, align 8
  %77 = call i32 @print_string(ptr noundef %75, ptr noundef %76)
  store i32 %77, ptr %3, align 4
  br label %87

78:                                               ; preds = %14
  %79 = load ptr, ptr %4, align 8
  %80 = load ptr, ptr %5, align 8
  %81 = call i32 @print_array(ptr noundef %79, ptr noundef %80)
  store i32 %81, ptr %3, align 4
  br label %87

82:                                               ; preds = %14
  %83 = load ptr, ptr %4, align 8
  %84 = load ptr, ptr %5, align 8
  %85 = call i32 @print_object(ptr noundef %83, ptr noundef %84)
  store i32 %85, ptr %3, align 4
  br label %87

86:                                               ; preds = %14
  store i32 0, ptr %3, align 4
  br label %87

87:                                               ; preds = %86, %82, %78, %74, %68, %67, %55, %46, %43, %42, %34, %33, %25, %24, %13
  %88 = load i32, ptr %3, align 4
  ret i32 %88
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @update_offset(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  store ptr null, ptr %3, align 8
  %4 = load ptr, ptr %2, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %11, label %6

6:                                                ; preds = %1
  %7 = load ptr, ptr %2, align 8
  %8 = getelementptr inbounds %struct.printbuffer, ptr %7, i32 0, i32 0
  %9 = load ptr, ptr %8, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %11, label %12

11:                                               ; preds = %6, %1
  br label %26

12:                                               ; preds = %6
  %13 = load ptr, ptr %2, align 8
  %14 = getelementptr inbounds %struct.printbuffer, ptr %13, i32 0, i32 0
  %15 = load ptr, ptr %14, align 8
  %16 = load ptr, ptr %2, align 8
  %17 = getelementptr inbounds %struct.printbuffer, ptr %16, i32 0, i32 2
  %18 = load i64, ptr %17, align 8
  %19 = getelementptr inbounds i8, ptr %15, i64 %18
  store ptr %19, ptr %3, align 8
  %20 = load ptr, ptr %3, align 8
  %21 = call i64 @strlen(ptr noundef %20) #9
  %22 = load ptr, ptr %2, align 8
  %23 = getelementptr inbounds %struct.printbuffer, ptr %22, i32 0, i32 2
  %24 = load i64, ptr %23, align 8
  %25 = add i64 %24, %21
  store i64 %25, ptr %23, align 8
  br label %26

26:                                               ; preds = %12, %11
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @ensure(ptr noundef %0, i64 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store i64 0, ptr %7, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %15, label %10

10:                                               ; preds = %2
  %11 = load ptr, ptr %4, align 8
  %12 = getelementptr inbounds %struct.printbuffer, ptr %11, i32 0, i32 0
  %13 = load ptr, ptr %12, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %10, %2
  store ptr null, ptr %3, align 8
  br label %152

16:                                               ; preds = %10
  %17 = load ptr, ptr %4, align 8
  %18 = getelementptr inbounds %struct.printbuffer, ptr %17, i32 0, i32 1
  %19 = load i64, ptr %18, align 8
  %20 = icmp ugt i64 %19, 0
  br i1 %20, label %21, label %30

21:                                               ; preds = %16
  %22 = load ptr, ptr %4, align 8
  %23 = getelementptr inbounds %struct.printbuffer, ptr %22, i32 0, i32 2
  %24 = load i64, ptr %23, align 8
  %25 = load ptr, ptr %4, align 8
  %26 = getelementptr inbounds %struct.printbuffer, ptr %25, i32 0, i32 1
  %27 = load i64, ptr %26, align 8
  %28 = icmp uge i64 %24, %27
  br i1 %28, label %29, label %30

29:                                               ; preds = %21
  store ptr null, ptr %3, align 8
  br label %152

30:                                               ; preds = %21, %16
  %31 = load i64, ptr %5, align 8
  %32 = icmp ugt i64 %31, 2147483647
  br i1 %32, label %33, label %34

33:                                               ; preds = %30
  store ptr null, ptr %3, align 8
  br label %152

34:                                               ; preds = %30
  %35 = load ptr, ptr %4, align 8
  %36 = getelementptr inbounds %struct.printbuffer, ptr %35, i32 0, i32 2
  %37 = load i64, ptr %36, align 8
  %38 = add i64 %37, 1
  %39 = load i64, ptr %5, align 8
  %40 = add i64 %39, %38
  store i64 %40, ptr %5, align 8
  %41 = load i64, ptr %5, align 8
  %42 = load ptr, ptr %4, align 8
  %43 = getelementptr inbounds %struct.printbuffer, ptr %42, i32 0, i32 1
  %44 = load i64, ptr %43, align 8
  %45 = icmp ule i64 %41, %44
  br i1 %45, label %46, label %54

46:                                               ; preds = %34
  %47 = load ptr, ptr %4, align 8
  %48 = getelementptr inbounds %struct.printbuffer, ptr %47, i32 0, i32 0
  %49 = load ptr, ptr %48, align 8
  %50 = load ptr, ptr %4, align 8
  %51 = getelementptr inbounds %struct.printbuffer, ptr %50, i32 0, i32 2
  %52 = load i64, ptr %51, align 8
  %53 = getelementptr inbounds i8, ptr %49, i64 %52
  store ptr %53, ptr %3, align 8
  br label %152

54:                                               ; preds = %34
  %55 = load ptr, ptr %4, align 8
  %56 = getelementptr inbounds %struct.printbuffer, ptr %55, i32 0, i32 4
  %57 = load i32, ptr %56, align 8
  %58 = icmp ne i32 %57, 0
  br i1 %58, label %59, label %60

59:                                               ; preds = %54
  store ptr null, ptr %3, align 8
  br label %152

60:                                               ; preds = %54
  %61 = load i64, ptr %5, align 8
  %62 = icmp ugt i64 %61, 1073741823
  br i1 %62, label %63, label %69

63:                                               ; preds = %60
  %64 = load i64, ptr %5, align 8
  %65 = icmp ule i64 %64, 2147483647
  br i1 %65, label %66, label %67

66:                                               ; preds = %63
  store i64 2147483647, ptr %7, align 8
  br label %68

67:                                               ; preds = %63
  store ptr null, ptr %3, align 8
  br label %152

68:                                               ; preds = %66
  br label %72

69:                                               ; preds = %60
  %70 = load i64, ptr %5, align 8
  %71 = mul i64 %70, 2
  store i64 %71, ptr %7, align 8
  br label %72

72:                                               ; preds = %69, %68
  %73 = load ptr, ptr %4, align 8
  %74 = getelementptr inbounds %struct.printbuffer, ptr %73, i32 0, i32 6
  %75 = getelementptr inbounds %struct.internal_hooks, ptr %74, i32 0, i32 2
  %76 = load ptr, ptr %75, align 8
  %77 = icmp ne ptr %76, null
  br i1 %77, label %78, label %103

78:                                               ; preds = %72
  %79 = load ptr, ptr %4, align 8
  %80 = getelementptr inbounds %struct.printbuffer, ptr %79, i32 0, i32 6
  %81 = getelementptr inbounds %struct.internal_hooks, ptr %80, i32 0, i32 2
  %82 = load ptr, ptr %81, align 8
  %83 = load ptr, ptr %4, align 8
  %84 = getelementptr inbounds %struct.printbuffer, ptr %83, i32 0, i32 0
  %85 = load ptr, ptr %84, align 8
  %86 = load i64, ptr %7, align 8
  %87 = call ptr %82(ptr noundef %85, i64 noundef %86)
  store ptr %87, ptr %6, align 8
  %88 = load ptr, ptr %6, align 8
  %89 = icmp eq ptr %88, null
  br i1 %89, label %90, label %102

90:                                               ; preds = %78
  %91 = load ptr, ptr %4, align 8
  %92 = getelementptr inbounds %struct.printbuffer, ptr %91, i32 0, i32 6
  %93 = getelementptr inbounds %struct.internal_hooks, ptr %92, i32 0, i32 1
  %94 = load ptr, ptr %93, align 8
  %95 = load ptr, ptr %4, align 8
  %96 = getelementptr inbounds %struct.printbuffer, ptr %95, i32 0, i32 0
  %97 = load ptr, ptr %96, align 8
  call void %94(ptr noundef %97)
  %98 = load ptr, ptr %4, align 8
  %99 = getelementptr inbounds %struct.printbuffer, ptr %98, i32 0, i32 1
  store i64 0, ptr %99, align 8
  %100 = load ptr, ptr %4, align 8
  %101 = getelementptr inbounds %struct.printbuffer, ptr %100, i32 0, i32 0
  store ptr null, ptr %101, align 8
  store ptr null, ptr %3, align 8
  br label %152

102:                                              ; preds = %78
  br label %140

103:                                              ; preds = %72
  %104 = load ptr, ptr %4, align 8
  %105 = getelementptr inbounds %struct.printbuffer, ptr %104, i32 0, i32 6
  %106 = getelementptr inbounds %struct.internal_hooks, ptr %105, i32 0, i32 0
  %107 = load ptr, ptr %106, align 8
  %108 = load i64, ptr %7, align 8
  %109 = call ptr %107(i64 noundef %108)
  store ptr %109, ptr %6, align 8
  %110 = load ptr, ptr %6, align 8
  %111 = icmp ne ptr %110, null
  br i1 %111, label %124, label %112

112:                                              ; preds = %103
  %113 = load ptr, ptr %4, align 8
  %114 = getelementptr inbounds %struct.printbuffer, ptr %113, i32 0, i32 6
  %115 = getelementptr inbounds %struct.internal_hooks, ptr %114, i32 0, i32 1
  %116 = load ptr, ptr %115, align 8
  %117 = load ptr, ptr %4, align 8
  %118 = getelementptr inbounds %struct.printbuffer, ptr %117, i32 0, i32 0
  %119 = load ptr, ptr %118, align 8
  call void %116(ptr noundef %119)
  %120 = load ptr, ptr %4, align 8
  %121 = getelementptr inbounds %struct.printbuffer, ptr %120, i32 0, i32 1
  store i64 0, ptr %121, align 8
  %122 = load ptr, ptr %4, align 8
  %123 = getelementptr inbounds %struct.printbuffer, ptr %122, i32 0, i32 0
  store ptr null, ptr %123, align 8
  store ptr null, ptr %3, align 8
  br label %152

124:                                              ; preds = %103
  %125 = load ptr, ptr %6, align 8
  %126 = load ptr, ptr %4, align 8
  %127 = getelementptr inbounds %struct.printbuffer, ptr %126, i32 0, i32 0
  %128 = load ptr, ptr %127, align 8
  %129 = load ptr, ptr %4, align 8
  %130 = getelementptr inbounds %struct.printbuffer, ptr %129, i32 0, i32 2
  %131 = load i64, ptr %130, align 8
  %132 = add i64 %131, 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %125, ptr align 1 %128, i64 %132, i1 false)
  %133 = load ptr, ptr %4, align 8
  %134 = getelementptr inbounds %struct.printbuffer, ptr %133, i32 0, i32 6
  %135 = getelementptr inbounds %struct.internal_hooks, ptr %134, i32 0, i32 1
  %136 = load ptr, ptr %135, align 8
  %137 = load ptr, ptr %4, align 8
  %138 = getelementptr inbounds %struct.printbuffer, ptr %137, i32 0, i32 0
  %139 = load ptr, ptr %138, align 8
  call void %136(ptr noundef %139)
  br label %140

140:                                              ; preds = %124, %102
  %141 = load i64, ptr %7, align 8
  %142 = load ptr, ptr %4, align 8
  %143 = getelementptr inbounds %struct.printbuffer, ptr %142, i32 0, i32 1
  store i64 %141, ptr %143, align 8
  %144 = load ptr, ptr %6, align 8
  %145 = load ptr, ptr %4, align 8
  %146 = getelementptr inbounds %struct.printbuffer, ptr %145, i32 0, i32 0
  store ptr %144, ptr %146, align 8
  %147 = load ptr, ptr %6, align 8
  %148 = load ptr, ptr %4, align 8
  %149 = getelementptr inbounds %struct.printbuffer, ptr %148, i32 0, i32 2
  %150 = load i64, ptr %149, align 8
  %151 = getelementptr inbounds i8, ptr %147, i64 %150
  store ptr %151, ptr %3, align 8
  br label %152

152:                                              ; preds = %140, %112, %90, %67, %59, %46, %33, %29, %15
  %153 = load ptr, ptr %3, align 8
  ret ptr %153
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_number(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca double, align 8
  %8 = alloca i32, align 4
  %9 = alloca i64, align 8
  %10 = alloca [26 x i8], align 1
  %11 = alloca i8, align 1
  %12 = alloca double, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %13 = load ptr, ptr %4, align 8
  %14 = getelementptr inbounds %struct.cJSON, ptr %13, i32 0, i32 6
  %15 = load double, ptr %14, align 8
  store double %15, ptr %7, align 8
  store i32 0, ptr %8, align 4
  store i64 0, ptr %9, align 8
  call void @llvm.memset.p0.i64(ptr align 1 %10, i8 0, i64 26, i1 false)
  %16 = call i8 @get_decimal_point()
  store i8 %16, ptr %11, align 1
  store double 0.000000e+00, ptr %12, align 8
  %17 = load ptr, ptr %5, align 8
  %18 = icmp eq ptr %17, null
  br i1 %18, label %19, label %20

19:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %120

20:                                               ; preds = %2
  %21 = load double, ptr %7, align 8
  %22 = fcmp uno double %21, %21
  br i1 %22, label %32, label %23

23:                                               ; preds = %20
  %24 = load double, ptr %7, align 8
  %25 = call double @llvm.fabs.f64(double %24) #10
  %26 = fcmp oeq double %25, 0x7FF0000000000000
  %27 = bitcast double %24 to i64
  %28 = icmp slt i64 %27, 0
  %29 = select i1 %28, i32 -1, i32 1
  %30 = select i1 %26, i32 %29, i32 0
  %31 = icmp ne i32 %30, 0
  br i1 %31, label %32, label %35

32:                                               ; preds = %23, %20
  %33 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 0
  %34 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %33, ptr noundef @.str.2) #8
  store i32 %34, ptr %8, align 4
  br label %66

35:                                               ; preds = %23
  %36 = load double, ptr %7, align 8
  %37 = load ptr, ptr %4, align 8
  %38 = getelementptr inbounds %struct.cJSON, ptr %37, i32 0, i32 5
  %39 = load i32, ptr %38, align 8
  %40 = sitofp i32 %39 to double
  %41 = fcmp oeq double %36, %40
  br i1 %41, label %42, label %48

42:                                               ; preds = %35
  %43 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 0
  %44 = load ptr, ptr %4, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 5
  %46 = load i32, ptr %45, align 8
  %47 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %43, ptr noundef @.str.5, i32 noundef %46) #8
  store i32 %47, ptr %8, align 4
  br label %65

48:                                               ; preds = %35
  %49 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 0
  %50 = load double, ptr %7, align 8
  %51 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %49, ptr noundef @.str.6, double noundef %50) #8
  store i32 %51, ptr %8, align 4
  %52 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 0
  %53 = call i32 (ptr, ptr, ...) @__isoc99_sscanf(ptr noundef %52, ptr noundef @.str.7, ptr noundef %12) #8
  %54 = icmp ne i32 %53, 1
  br i1 %54, label %60, label %55

55:                                               ; preds = %48
  %56 = load double, ptr %12, align 8
  %57 = load double, ptr %7, align 8
  %58 = call i32 @compare_double(double noundef %56, double noundef %57)
  %59 = icmp ne i32 %58, 0
  br i1 %59, label %64, label %60

60:                                               ; preds = %55, %48
  %61 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 0
  %62 = load double, ptr %7, align 8
  %63 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %61, ptr noundef @.str.8, double noundef %62) #8
  store i32 %63, ptr %8, align 4
  br label %64

64:                                               ; preds = %60, %55
  br label %65

65:                                               ; preds = %64, %42
  br label %66

66:                                               ; preds = %65, %32
  %67 = load i32, ptr %8, align 4
  %68 = icmp slt i32 %67, 0
  br i1 %68, label %72, label %69

69:                                               ; preds = %66
  %70 = load i32, ptr %8, align 4
  %71 = icmp sgt i32 %70, 25
  br i1 %71, label %72, label %73

72:                                               ; preds = %69, %66
  store i32 0, ptr %3, align 4
  br label %120

73:                                               ; preds = %69
  %74 = load ptr, ptr %5, align 8
  %75 = load i32, ptr %8, align 4
  %76 = sext i32 %75 to i64
  %77 = add i64 %76, 1
  %78 = call ptr @ensure(ptr noundef %74, i64 noundef %77)
  store ptr %78, ptr %6, align 8
  %79 = load ptr, ptr %6, align 8
  %80 = icmp eq ptr %79, null
  br i1 %80, label %81, label %82

81:                                               ; preds = %73
  store i32 0, ptr %3, align 4
  br label %120

82:                                               ; preds = %73
  store i64 0, ptr %9, align 8
  br label %83

83:                                               ; preds = %107, %82
  %84 = load i64, ptr %9, align 8
  %85 = load i32, ptr %8, align 4
  %86 = sext i32 %85 to i64
  %87 = icmp ult i64 %84, %86
  br i1 %87, label %88, label %110

88:                                               ; preds = %83
  %89 = load i64, ptr %9, align 8
  %90 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 %89
  %91 = load i8, ptr %90, align 1
  %92 = zext i8 %91 to i32
  %93 = load i8, ptr %11, align 1
  %94 = zext i8 %93 to i32
  %95 = icmp eq i32 %92, %94
  br i1 %95, label %96, label %100

96:                                               ; preds = %88
  %97 = load ptr, ptr %6, align 8
  %98 = load i64, ptr %9, align 8
  %99 = getelementptr inbounds i8, ptr %97, i64 %98
  store i8 46, ptr %99, align 1
  br label %107

100:                                              ; preds = %88
  %101 = load i64, ptr %9, align 8
  %102 = getelementptr inbounds [26 x i8], ptr %10, i64 0, i64 %101
  %103 = load i8, ptr %102, align 1
  %104 = load ptr, ptr %6, align 8
  %105 = load i64, ptr %9, align 8
  %106 = getelementptr inbounds i8, ptr %104, i64 %105
  store i8 %103, ptr %106, align 1
  br label %107

107:                                              ; preds = %100, %96
  %108 = load i64, ptr %9, align 8
  %109 = add i64 %108, 1
  store i64 %109, ptr %9, align 8
  br label %83, !llvm.loop !17

110:                                              ; preds = %83
  %111 = load ptr, ptr %6, align 8
  %112 = load i64, ptr %9, align 8
  %113 = getelementptr inbounds i8, ptr %111, i64 %112
  store i8 0, ptr %113, align 1
  %114 = load i32, ptr %8, align 4
  %115 = sext i32 %114 to i64
  %116 = load ptr, ptr %5, align 8
  %117 = getelementptr inbounds %struct.printbuffer, ptr %116, i32 0, i32 2
  %118 = load i64, ptr %117, align 8
  %119 = add i64 %118, %115
  store i64 %119, ptr %117, align 8
  store i32 1, ptr %3, align 4
  br label %120

120:                                              ; preds = %110, %81, %72, %19
  %121 = load i32, ptr %3, align 4
  ret i32 %121
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_string(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = getelementptr inbounds %struct.cJSON, ptr %5, i32 0, i32 4
  %7 = load ptr, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = call i32 @print_string_ptr(ptr noundef %7, ptr noundef %8)
  ret i32 %9
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_array(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store i64 0, ptr %7, align 8
  %9 = load ptr, ptr %4, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 2
  %11 = load ptr, ptr %10, align 8
  store ptr %11, ptr %8, align 8
  %12 = load ptr, ptr %5, align 8
  %13 = icmp eq ptr %12, null
  br i1 %13, label %14, label %15

14:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %96

15:                                               ; preds = %2
  %16 = load ptr, ptr %5, align 8
  %17 = call ptr @ensure(ptr noundef %16, i64 noundef 1)
  store ptr %17, ptr %6, align 8
  %18 = load ptr, ptr %6, align 8
  %19 = icmp eq ptr %18, null
  br i1 %19, label %20, label %21

20:                                               ; preds = %15
  store i32 0, ptr %3, align 4
  br label %96

21:                                               ; preds = %15
  %22 = load ptr, ptr %6, align 8
  store i8 91, ptr %22, align 1
  %23 = load ptr, ptr %5, align 8
  %24 = getelementptr inbounds %struct.printbuffer, ptr %23, i32 0, i32 2
  %25 = load i64, ptr %24, align 8
  %26 = add i64 %25, 1
  store i64 %26, ptr %24, align 8
  %27 = load ptr, ptr %5, align 8
  %28 = getelementptr inbounds %struct.printbuffer, ptr %27, i32 0, i32 3
  %29 = load i64, ptr %28, align 8
  %30 = add i64 %29, 1
  store i64 %30, ptr %28, align 8
  br label %31

31:                                               ; preds = %78, %21
  %32 = load ptr, ptr %8, align 8
  %33 = icmp ne ptr %32, null
  br i1 %33, label %34, label %82

34:                                               ; preds = %31
  %35 = load ptr, ptr %8, align 8
  %36 = load ptr, ptr %5, align 8
  %37 = call i32 @print_value(ptr noundef %35, ptr noundef %36)
  %38 = icmp ne i32 %37, 0
  br i1 %38, label %40, label %39

39:                                               ; preds = %34
  store i32 0, ptr %3, align 4
  br label %96

40:                                               ; preds = %34
  %41 = load ptr, ptr %5, align 8
  call void @update_offset(ptr noundef %41)
  %42 = load ptr, ptr %8, align 8
  %43 = getelementptr inbounds %struct.cJSON, ptr %42, i32 0, i32 0
  %44 = load ptr, ptr %43, align 8
  %45 = icmp ne ptr %44, null
  br i1 %45, label %46, label %78

46:                                               ; preds = %40
  %47 = load ptr, ptr %5, align 8
  %48 = getelementptr inbounds %struct.printbuffer, ptr %47, i32 0, i32 5
  %49 = load i32, ptr %48, align 4
  %50 = icmp ne i32 %49, 0
  %51 = zext i1 %50 to i64
  %52 = select i1 %50, i32 2, i32 1
  %53 = sext i32 %52 to i64
  store i64 %53, ptr %7, align 8
  %54 = load ptr, ptr %5, align 8
  %55 = load i64, ptr %7, align 8
  %56 = add i64 %55, 1
  %57 = call ptr @ensure(ptr noundef %54, i64 noundef %56)
  store ptr %57, ptr %6, align 8
  %58 = load ptr, ptr %6, align 8
  %59 = icmp eq ptr %58, null
  br i1 %59, label %60, label %61

60:                                               ; preds = %46
  store i32 0, ptr %3, align 4
  br label %96

61:                                               ; preds = %46
  %62 = load ptr, ptr %6, align 8
  %63 = getelementptr inbounds i8, ptr %62, i32 1
  store ptr %63, ptr %6, align 8
  store i8 44, ptr %62, align 1
  %64 = load ptr, ptr %5, align 8
  %65 = getelementptr inbounds %struct.printbuffer, ptr %64, i32 0, i32 5
  %66 = load i32, ptr %65, align 4
  %67 = icmp ne i32 %66, 0
  br i1 %67, label %68, label %71

68:                                               ; preds = %61
  %69 = load ptr, ptr %6, align 8
  %70 = getelementptr inbounds i8, ptr %69, i32 1
  store ptr %70, ptr %6, align 8
  store i8 32, ptr %69, align 1
  br label %71

71:                                               ; preds = %68, %61
  %72 = load ptr, ptr %6, align 8
  store i8 0, ptr %72, align 1
  %73 = load i64, ptr %7, align 8
  %74 = load ptr, ptr %5, align 8
  %75 = getelementptr inbounds %struct.printbuffer, ptr %74, i32 0, i32 2
  %76 = load i64, ptr %75, align 8
  %77 = add i64 %76, %73
  store i64 %77, ptr %75, align 8
  br label %78

78:                                               ; preds = %71, %40
  %79 = load ptr, ptr %8, align 8
  %80 = getelementptr inbounds %struct.cJSON, ptr %79, i32 0, i32 0
  %81 = load ptr, ptr %80, align 8
  store ptr %81, ptr %8, align 8
  br label %31, !llvm.loop !18

82:                                               ; preds = %31
  %83 = load ptr, ptr %5, align 8
  %84 = call ptr @ensure(ptr noundef %83, i64 noundef 2)
  store ptr %84, ptr %6, align 8
  %85 = load ptr, ptr %6, align 8
  %86 = icmp eq ptr %85, null
  br i1 %86, label %87, label %88

87:                                               ; preds = %82
  store i32 0, ptr %3, align 4
  br label %96

88:                                               ; preds = %82
  %89 = load ptr, ptr %6, align 8
  %90 = getelementptr inbounds i8, ptr %89, i32 1
  store ptr %90, ptr %6, align 8
  store i8 93, ptr %89, align 1
  %91 = load ptr, ptr %6, align 8
  store i8 0, ptr %91, align 1
  %92 = load ptr, ptr %5, align 8
  %93 = getelementptr inbounds %struct.printbuffer, ptr %92, i32 0, i32 3
  %94 = load i64, ptr %93, align 8
  %95 = add i64 %94, -1
  store i64 %95, ptr %93, align 8
  store i32 1, ptr %3, align 4
  br label %96

96:                                               ; preds = %88, %87, %60, %39, %20, %14
  %97 = load i32, ptr %3, align 4
  ret i32 %97
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_object(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i64, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i64, align 8
  %10 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store i64 0, ptr %7, align 8
  %11 = load ptr, ptr %4, align 8
  %12 = getelementptr inbounds %struct.cJSON, ptr %11, i32 0, i32 2
  %13 = load ptr, ptr %12, align 8
  store ptr %13, ptr %8, align 8
  %14 = load ptr, ptr %5, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %16, label %17

16:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %230

17:                                               ; preds = %2
  %18 = load ptr, ptr %5, align 8
  %19 = getelementptr inbounds %struct.printbuffer, ptr %18, i32 0, i32 5
  %20 = load i32, ptr %19, align 4
  %21 = icmp ne i32 %20, 0
  %22 = zext i1 %21 to i64
  %23 = select i1 %21, i32 2, i32 1
  %24 = sext i32 %23 to i64
  store i64 %24, ptr %7, align 8
  %25 = load ptr, ptr %5, align 8
  %26 = load i64, ptr %7, align 8
  %27 = add i64 %26, 1
  %28 = call ptr @ensure(ptr noundef %25, i64 noundef %27)
  store ptr %28, ptr %6, align 8
  %29 = load ptr, ptr %6, align 8
  %30 = icmp eq ptr %29, null
  br i1 %30, label %31, label %32

31:                                               ; preds = %17
  store i32 0, ptr %3, align 4
  br label %230

32:                                               ; preds = %17
  %33 = load ptr, ptr %6, align 8
  %34 = getelementptr inbounds i8, ptr %33, i32 1
  store ptr %34, ptr %6, align 8
  store i8 123, ptr %33, align 1
  %35 = load ptr, ptr %5, align 8
  %36 = getelementptr inbounds %struct.printbuffer, ptr %35, i32 0, i32 3
  %37 = load i64, ptr %36, align 8
  %38 = add i64 %37, 1
  store i64 %38, ptr %36, align 8
  %39 = load ptr, ptr %5, align 8
  %40 = getelementptr inbounds %struct.printbuffer, ptr %39, i32 0, i32 5
  %41 = load i32, ptr %40, align 4
  %42 = icmp ne i32 %41, 0
  br i1 %42, label %43, label %46

43:                                               ; preds = %32
  %44 = load ptr, ptr %6, align 8
  %45 = getelementptr inbounds i8, ptr %44, i32 1
  store ptr %45, ptr %6, align 8
  store i8 10, ptr %44, align 1
  br label %46

46:                                               ; preds = %43, %32
  %47 = load i64, ptr %7, align 8
  %48 = load ptr, ptr %5, align 8
  %49 = getelementptr inbounds %struct.printbuffer, ptr %48, i32 0, i32 2
  %50 = load i64, ptr %49, align 8
  %51 = add i64 %50, %47
  store i64 %51, ptr %49, align 8
  br label %52

52:                                               ; preds = %174, %46
  %53 = load ptr, ptr %8, align 8
  %54 = icmp ne ptr %53, null
  br i1 %54, label %55, label %184

55:                                               ; preds = %52
  %56 = load ptr, ptr %5, align 8
  %57 = getelementptr inbounds %struct.printbuffer, ptr %56, i32 0, i32 5
  %58 = load i32, ptr %57, align 4
  %59 = icmp ne i32 %58, 0
  br i1 %59, label %60, label %90

60:                                               ; preds = %55
  %61 = load ptr, ptr %5, align 8
  %62 = load ptr, ptr %5, align 8
  %63 = getelementptr inbounds %struct.printbuffer, ptr %62, i32 0, i32 3
  %64 = load i64, ptr %63, align 8
  %65 = call ptr @ensure(ptr noundef %61, i64 noundef %64)
  store ptr %65, ptr %6, align 8
  %66 = load ptr, ptr %6, align 8
  %67 = icmp eq ptr %66, null
  br i1 %67, label %68, label %69

68:                                               ; preds = %60
  store i32 0, ptr %3, align 4
  br label %230

69:                                               ; preds = %60
  store i64 0, ptr %9, align 8
  br label %70

70:                                               ; preds = %79, %69
  %71 = load i64, ptr %9, align 8
  %72 = load ptr, ptr %5, align 8
  %73 = getelementptr inbounds %struct.printbuffer, ptr %72, i32 0, i32 3
  %74 = load i64, ptr %73, align 8
  %75 = icmp ult i64 %71, %74
  br i1 %75, label %76, label %82

76:                                               ; preds = %70
  %77 = load ptr, ptr %6, align 8
  %78 = getelementptr inbounds i8, ptr %77, i32 1
  store ptr %78, ptr %6, align 8
  store i8 9, ptr %77, align 1
  br label %79

79:                                               ; preds = %76
  %80 = load i64, ptr %9, align 8
  %81 = add i64 %80, 1
  store i64 %81, ptr %9, align 8
  br label %70, !llvm.loop !19

82:                                               ; preds = %70
  %83 = load ptr, ptr %5, align 8
  %84 = getelementptr inbounds %struct.printbuffer, ptr %83, i32 0, i32 3
  %85 = load i64, ptr %84, align 8
  %86 = load ptr, ptr %5, align 8
  %87 = getelementptr inbounds %struct.printbuffer, ptr %86, i32 0, i32 2
  %88 = load i64, ptr %87, align 8
  %89 = add i64 %88, %85
  store i64 %89, ptr %87, align 8
  br label %90

90:                                               ; preds = %82, %55
  %91 = load ptr, ptr %8, align 8
  %92 = getelementptr inbounds %struct.cJSON, ptr %91, i32 0, i32 7
  %93 = load ptr, ptr %92, align 8
  %94 = load ptr, ptr %5, align 8
  %95 = call i32 @print_string_ptr(ptr noundef %93, ptr noundef %94)
  %96 = icmp ne i32 %95, 0
  br i1 %96, label %98, label %97

97:                                               ; preds = %90
  store i32 0, ptr %3, align 4
  br label %230

98:                                               ; preds = %90
  %99 = load ptr, ptr %5, align 8
  call void @update_offset(ptr noundef %99)
  %100 = load ptr, ptr %5, align 8
  %101 = getelementptr inbounds %struct.printbuffer, ptr %100, i32 0, i32 5
  %102 = load i32, ptr %101, align 4
  %103 = icmp ne i32 %102, 0
  %104 = zext i1 %103 to i64
  %105 = select i1 %103, i32 2, i32 1
  %106 = sext i32 %105 to i64
  store i64 %106, ptr %7, align 8
  %107 = load ptr, ptr %5, align 8
  %108 = load i64, ptr %7, align 8
  %109 = call ptr @ensure(ptr noundef %107, i64 noundef %108)
  store ptr %109, ptr %6, align 8
  %110 = load ptr, ptr %6, align 8
  %111 = icmp eq ptr %110, null
  br i1 %111, label %112, label %113

112:                                              ; preds = %98
  store i32 0, ptr %3, align 4
  br label %230

113:                                              ; preds = %98
  %114 = load ptr, ptr %6, align 8
  %115 = getelementptr inbounds i8, ptr %114, i32 1
  store ptr %115, ptr %6, align 8
  store i8 58, ptr %114, align 1
  %116 = load ptr, ptr %5, align 8
  %117 = getelementptr inbounds %struct.printbuffer, ptr %116, i32 0, i32 5
  %118 = load i32, ptr %117, align 4
  %119 = icmp ne i32 %118, 0
  br i1 %119, label %120, label %123

120:                                              ; preds = %113
  %121 = load ptr, ptr %6, align 8
  %122 = getelementptr inbounds i8, ptr %121, i32 1
  store ptr %122, ptr %6, align 8
  store i8 9, ptr %121, align 1
  br label %123

123:                                              ; preds = %120, %113
  %124 = load i64, ptr %7, align 8
  %125 = load ptr, ptr %5, align 8
  %126 = getelementptr inbounds %struct.printbuffer, ptr %125, i32 0, i32 2
  %127 = load i64, ptr %126, align 8
  %128 = add i64 %127, %124
  store i64 %128, ptr %126, align 8
  %129 = load ptr, ptr %8, align 8
  %130 = load ptr, ptr %5, align 8
  %131 = call i32 @print_value(ptr noundef %129, ptr noundef %130)
  %132 = icmp ne i32 %131, 0
  br i1 %132, label %134, label %133

133:                                              ; preds = %123
  store i32 0, ptr %3, align 4
  br label %230

134:                                              ; preds = %123
  %135 = load ptr, ptr %5, align 8
  call void @update_offset(ptr noundef %135)
  %136 = load ptr, ptr %5, align 8
  %137 = getelementptr inbounds %struct.printbuffer, ptr %136, i32 0, i32 5
  %138 = load i32, ptr %137, align 4
  %139 = icmp ne i32 %138, 0
  %140 = zext i1 %139 to i64
  %141 = select i1 %139, i32 1, i32 0
  %142 = sext i32 %141 to i64
  %143 = load ptr, ptr %8, align 8
  %144 = getelementptr inbounds %struct.cJSON, ptr %143, i32 0, i32 0
  %145 = load ptr, ptr %144, align 8
  %146 = icmp ne ptr %145, null
  %147 = zext i1 %146 to i64
  %148 = select i1 %146, i32 1, i32 0
  %149 = sext i32 %148 to i64
  %150 = add i64 %142, %149
  store i64 %150, ptr %7, align 8
  %151 = load ptr, ptr %5, align 8
  %152 = load i64, ptr %7, align 8
  %153 = add i64 %152, 1
  %154 = call ptr @ensure(ptr noundef %151, i64 noundef %153)
  store ptr %154, ptr %6, align 8
  %155 = load ptr, ptr %6, align 8
  %156 = icmp eq ptr %155, null
  br i1 %156, label %157, label %158

157:                                              ; preds = %134
  store i32 0, ptr %3, align 4
  br label %230

158:                                              ; preds = %134
  %159 = load ptr, ptr %8, align 8
  %160 = getelementptr inbounds %struct.cJSON, ptr %159, i32 0, i32 0
  %161 = load ptr, ptr %160, align 8
  %162 = icmp ne ptr %161, null
  br i1 %162, label %163, label %166

163:                                              ; preds = %158
  %164 = load ptr, ptr %6, align 8
  %165 = getelementptr inbounds i8, ptr %164, i32 1
  store ptr %165, ptr %6, align 8
  store i8 44, ptr %164, align 1
  br label %166

166:                                              ; preds = %163, %158
  %167 = load ptr, ptr %5, align 8
  %168 = getelementptr inbounds %struct.printbuffer, ptr %167, i32 0, i32 5
  %169 = load i32, ptr %168, align 4
  %170 = icmp ne i32 %169, 0
  br i1 %170, label %171, label %174

171:                                              ; preds = %166
  %172 = load ptr, ptr %6, align 8
  %173 = getelementptr inbounds i8, ptr %172, i32 1
  store ptr %173, ptr %6, align 8
  store i8 10, ptr %172, align 1
  br label %174

174:                                              ; preds = %171, %166
  %175 = load ptr, ptr %6, align 8
  store i8 0, ptr %175, align 1
  %176 = load i64, ptr %7, align 8
  %177 = load ptr, ptr %5, align 8
  %178 = getelementptr inbounds %struct.printbuffer, ptr %177, i32 0, i32 2
  %179 = load i64, ptr %178, align 8
  %180 = add i64 %179, %176
  store i64 %180, ptr %178, align 8
  %181 = load ptr, ptr %8, align 8
  %182 = getelementptr inbounds %struct.cJSON, ptr %181, i32 0, i32 0
  %183 = load ptr, ptr %182, align 8
  store ptr %183, ptr %8, align 8
  br label %52, !llvm.loop !20

184:                                              ; preds = %52
  %185 = load ptr, ptr %5, align 8
  %186 = load ptr, ptr %5, align 8
  %187 = getelementptr inbounds %struct.printbuffer, ptr %186, i32 0, i32 5
  %188 = load i32, ptr %187, align 4
  %189 = icmp ne i32 %188, 0
  br i1 %189, label %190, label %195

190:                                              ; preds = %184
  %191 = load ptr, ptr %5, align 8
  %192 = getelementptr inbounds %struct.printbuffer, ptr %191, i32 0, i32 3
  %193 = load i64, ptr %192, align 8
  %194 = add i64 %193, 1
  br label %196

195:                                              ; preds = %184
  br label %196

196:                                              ; preds = %195, %190
  %197 = phi i64 [ %194, %190 ], [ 2, %195 ]
  %198 = call ptr @ensure(ptr noundef %185, i64 noundef %197)
  store ptr %198, ptr %6, align 8
  %199 = load ptr, ptr %6, align 8
  %200 = icmp eq ptr %199, null
  br i1 %200, label %201, label %202

201:                                              ; preds = %196
  store i32 0, ptr %3, align 4
  br label %230

202:                                              ; preds = %196
  %203 = load ptr, ptr %5, align 8
  %204 = getelementptr inbounds %struct.printbuffer, ptr %203, i32 0, i32 5
  %205 = load i32, ptr %204, align 4
  %206 = icmp ne i32 %205, 0
  br i1 %206, label %207, label %222

207:                                              ; preds = %202
  store i64 0, ptr %10, align 8
  br label %208

208:                                              ; preds = %218, %207
  %209 = load i64, ptr %10, align 8
  %210 = load ptr, ptr %5, align 8
  %211 = getelementptr inbounds %struct.printbuffer, ptr %210, i32 0, i32 3
  %212 = load i64, ptr %211, align 8
  %213 = sub i64 %212, 1
  %214 = icmp ult i64 %209, %213
  br i1 %214, label %215, label %221

215:                                              ; preds = %208
  %216 = load ptr, ptr %6, align 8
  %217 = getelementptr inbounds i8, ptr %216, i32 1
  store ptr %217, ptr %6, align 8
  store i8 9, ptr %216, align 1
  br label %218

218:                                              ; preds = %215
  %219 = load i64, ptr %10, align 8
  %220 = add i64 %219, 1
  store i64 %220, ptr %10, align 8
  br label %208, !llvm.loop !21

221:                                              ; preds = %208
  br label %222

222:                                              ; preds = %221, %202
  %223 = load ptr, ptr %6, align 8
  %224 = getelementptr inbounds i8, ptr %223, i32 1
  store ptr %224, ptr %6, align 8
  store i8 125, ptr %223, align 1
  %225 = load ptr, ptr %6, align 8
  store i8 0, ptr %225, align 1
  %226 = load ptr, ptr %5, align 8
  %227 = getelementptr inbounds %struct.printbuffer, ptr %226, i32 0, i32 3
  %228 = load i64, ptr %227, align 8
  %229 = add i64 %228, -1
  store i64 %229, ptr %227, align 8
  store i32 1, ptr %3, align 4
  br label %230

230:                                              ; preds = %222, %201, %157, %133, %112, %97, %68, %31, %16
  %231 = load i32, ptr %3, align 4
  ret i32 %231
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @print_string_ptr(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i64, align 8
  %10 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store i64 0, ptr %9, align 8
  store i64 0, ptr %10, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %159

14:                                               ; preds = %2
  %15 = load ptr, ptr %4, align 8
  %16 = icmp eq ptr %15, null
  br i1 %16, label %17, label %26

17:                                               ; preds = %14
  %18 = load ptr, ptr %5, align 8
  %19 = call ptr @ensure(ptr noundef %18, i64 noundef 3)
  store ptr %19, ptr %7, align 8
  %20 = load ptr, ptr %7, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %22, label %23

22:                                               ; preds = %17
  store i32 0, ptr %3, align 4
  br label %159

23:                                               ; preds = %17
  %24 = load ptr, ptr %7, align 8
  %25 = call ptr @strcpy(ptr noundef %24, ptr noundef @.str.9) #8
  store i32 1, ptr %3, align 4
  br label %159

26:                                               ; preds = %14
  %27 = load ptr, ptr %4, align 8
  store ptr %27, ptr %6, align 8
  br label %28

28:                                               ; preds = %49, %26
  %29 = load ptr, ptr %6, align 8
  %30 = load i8, ptr %29, align 1
  %31 = icmp ne i8 %30, 0
  br i1 %31, label %32, label %52

32:                                               ; preds = %28
  %33 = load ptr, ptr %6, align 8
  %34 = load i8, ptr %33, align 1
  %35 = zext i8 %34 to i32
  switch i32 %35, label %39 [
    i32 34, label %36
    i32 92, label %36
    i32 8, label %36
    i32 12, label %36
    i32 10, label %36
    i32 13, label %36
    i32 9, label %36
  ]

36:                                               ; preds = %32, %32, %32, %32, %32, %32, %32
  %37 = load i64, ptr %10, align 8
  %38 = add i64 %37, 1
  store i64 %38, ptr %10, align 8
  br label %48

39:                                               ; preds = %32
  %40 = load ptr, ptr %6, align 8
  %41 = load i8, ptr %40, align 1
  %42 = zext i8 %41 to i32
  %43 = icmp slt i32 %42, 32
  br i1 %43, label %44, label %47

44:                                               ; preds = %39
  %45 = load i64, ptr %10, align 8
  %46 = add i64 %45, 5
  store i64 %46, ptr %10, align 8
  br label %47

47:                                               ; preds = %44, %39
  br label %48

48:                                               ; preds = %47, %36
  br label %49

49:                                               ; preds = %48
  %50 = load ptr, ptr %6, align 8
  %51 = getelementptr inbounds i8, ptr %50, i32 1
  store ptr %51, ptr %6, align 8
  br label %28, !llvm.loop !22

52:                                               ; preds = %28
  %53 = load ptr, ptr %6, align 8
  %54 = load ptr, ptr %4, align 8
  %55 = ptrtoint ptr %53 to i64
  %56 = ptrtoint ptr %54 to i64
  %57 = sub i64 %55, %56
  %58 = load i64, ptr %10, align 8
  %59 = add i64 %57, %58
  store i64 %59, ptr %9, align 8
  %60 = load ptr, ptr %5, align 8
  %61 = load i64, ptr %9, align 8
  %62 = add i64 %61, 3
  %63 = call ptr @ensure(ptr noundef %60, i64 noundef %62)
  store ptr %63, ptr %7, align 8
  %64 = load ptr, ptr %7, align 8
  %65 = icmp eq ptr %64, null
  br i1 %65, label %66, label %67

66:                                               ; preds = %52
  store i32 0, ptr %3, align 4
  br label %159

67:                                               ; preds = %52
  %68 = load i64, ptr %10, align 8
  %69 = icmp eq i64 %68, 0
  br i1 %69, label %70, label %85

70:                                               ; preds = %67
  %71 = load ptr, ptr %7, align 8
  %72 = getelementptr inbounds i8, ptr %71, i64 0
  store i8 34, ptr %72, align 1
  %73 = load ptr, ptr %7, align 8
  %74 = getelementptr inbounds i8, ptr %73, i64 1
  %75 = load ptr, ptr %4, align 8
  %76 = load i64, ptr %9, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %74, ptr align 1 %75, i64 %76, i1 false)
  %77 = load ptr, ptr %7, align 8
  %78 = load i64, ptr %9, align 8
  %79 = add i64 %78, 1
  %80 = getelementptr inbounds i8, ptr %77, i64 %79
  store i8 34, ptr %80, align 1
  %81 = load ptr, ptr %7, align 8
  %82 = load i64, ptr %9, align 8
  %83 = add i64 %82, 2
  %84 = getelementptr inbounds i8, ptr %81, i64 %83
  store i8 0, ptr %84, align 1
  store i32 1, ptr %3, align 4
  br label %159

85:                                               ; preds = %67
  %86 = load ptr, ptr %7, align 8
  %87 = getelementptr inbounds i8, ptr %86, i64 0
  store i8 34, ptr %87, align 1
  %88 = load ptr, ptr %7, align 8
  %89 = getelementptr inbounds i8, ptr %88, i64 1
  store ptr %89, ptr %8, align 8
  %90 = load ptr, ptr %4, align 8
  store ptr %90, ptr %6, align 8
  br label %91

91:                                               ; preds = %145, %85
  %92 = load ptr, ptr %6, align 8
  %93 = load i8, ptr %92, align 1
  %94 = zext i8 %93 to i32
  %95 = icmp ne i32 %94, 0
  br i1 %95, label %96, label %150

96:                                               ; preds = %91
  %97 = load ptr, ptr %6, align 8
  %98 = load i8, ptr %97, align 1
  %99 = zext i8 %98 to i32
  %100 = icmp sgt i32 %99, 31
  br i1 %100, label %101, label %115

101:                                              ; preds = %96
  %102 = load ptr, ptr %6, align 8
  %103 = load i8, ptr %102, align 1
  %104 = zext i8 %103 to i32
  %105 = icmp ne i32 %104, 34
  br i1 %105, label %106, label %115

106:                                              ; preds = %101
  %107 = load ptr, ptr %6, align 8
  %108 = load i8, ptr %107, align 1
  %109 = zext i8 %108 to i32
  %110 = icmp ne i32 %109, 92
  br i1 %110, label %111, label %115

111:                                              ; preds = %106
  %112 = load ptr, ptr %6, align 8
  %113 = load i8, ptr %112, align 1
  %114 = load ptr, ptr %8, align 8
  store i8 %113, ptr %114, align 1
  br label %144

115:                                              ; preds = %106, %101, %96
  %116 = load ptr, ptr %8, align 8
  %117 = getelementptr inbounds i8, ptr %116, i32 1
  store ptr %117, ptr %8, align 8
  store i8 92, ptr %116, align 1
  %118 = load ptr, ptr %6, align 8
  %119 = load i8, ptr %118, align 1
  %120 = zext i8 %119 to i32
  switch i32 %120, label %135 [
    i32 92, label %121
    i32 34, label %123
    i32 8, label %125
    i32 12, label %127
    i32 10, label %129
    i32 13, label %131
    i32 9, label %133
  ]

121:                                              ; preds = %115
  %122 = load ptr, ptr %8, align 8
  store i8 92, ptr %122, align 1
  br label %143

123:                                              ; preds = %115
  %124 = load ptr, ptr %8, align 8
  store i8 34, ptr %124, align 1
  br label %143

125:                                              ; preds = %115
  %126 = load ptr, ptr %8, align 8
  store i8 98, ptr %126, align 1
  br label %143

127:                                              ; preds = %115
  %128 = load ptr, ptr %8, align 8
  store i8 102, ptr %128, align 1
  br label %143

129:                                              ; preds = %115
  %130 = load ptr, ptr %8, align 8
  store i8 110, ptr %130, align 1
  br label %143

131:                                              ; preds = %115
  %132 = load ptr, ptr %8, align 8
  store i8 114, ptr %132, align 1
  br label %143

133:                                              ; preds = %115
  %134 = load ptr, ptr %8, align 8
  store i8 116, ptr %134, align 1
  br label %143

135:                                              ; preds = %115
  %136 = load ptr, ptr %8, align 8
  %137 = load ptr, ptr %6, align 8
  %138 = load i8, ptr %137, align 1
  %139 = zext i8 %138 to i32
  %140 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %136, ptr noundef @.str.10, i32 noundef %139) #8
  %141 = load ptr, ptr %8, align 8
  %142 = getelementptr inbounds i8, ptr %141, i64 4
  store ptr %142, ptr %8, align 8
  br label %143

143:                                              ; preds = %135, %133, %131, %129, %127, %125, %123, %121
  br label %144

144:                                              ; preds = %143, %111
  br label %145

145:                                              ; preds = %144
  %146 = load ptr, ptr %6, align 8
  %147 = getelementptr inbounds i8, ptr %146, i32 1
  store ptr %147, ptr %6, align 8
  %148 = load ptr, ptr %8, align 8
  %149 = getelementptr inbounds i8, ptr %148, i32 1
  store ptr %149, ptr %8, align 8
  br label %91, !llvm.loop !23

150:                                              ; preds = %91
  %151 = load ptr, ptr %7, align 8
  %152 = load i64, ptr %9, align 8
  %153 = add i64 %152, 1
  %154 = getelementptr inbounds i8, ptr %151, i64 %153
  store i8 34, ptr %154, align 1
  %155 = load ptr, ptr %7, align 8
  %156 = load i64, ptr %9, align 8
  %157 = add i64 %156, 2
  %158 = getelementptr inbounds i8, ptr %155, i64 %157
  store i8 0, ptr %158, align 1
  store i32 1, ptr %3, align 4
  br label %159

159:                                              ; preds = %150, %70, %66, %23, %22, %13
  %160 = load i32, ptr %3, align 4
  ret i32 %160
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare double @llvm.fabs.f64(double) #7

; Function Attrs: nounwind
declare i32 @__isoc99_sscanf(ptr noundef, ptr noundef, ...) #1

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @compare_double(double noundef %0, double noundef %1) #0 {
  %3 = alloca double, align 8
  %4 = alloca double, align 8
  %5 = alloca double, align 8
  store double %0, ptr %3, align 8
  store double %1, ptr %4, align 8
  %6 = load double, ptr %3, align 8
  %7 = call double @llvm.fabs.f64(double %6)
  %8 = load double, ptr %4, align 8
  %9 = call double @llvm.fabs.f64(double %8)
  %10 = fcmp ogt double %7, %9
  br i1 %10, label %11, label %14

11:                                               ; preds = %2
  %12 = load double, ptr %3, align 8
  %13 = call double @llvm.fabs.f64(double %12)
  br label %17

14:                                               ; preds = %2
  %15 = load double, ptr %4, align 8
  %16 = call double @llvm.fabs.f64(double %15)
  br label %17

17:                                               ; preds = %14, %11
  %18 = phi double [ %13, %11 ], [ %16, %14 ]
  store double %18, ptr %5, align 8
  %19 = load double, ptr %3, align 8
  %20 = load double, ptr %4, align 8
  %21 = fsub double %19, %20
  %22 = call double @llvm.fabs.f64(double %21)
  %23 = load double, ptr %5, align 8
  %24 = fmul double %23, 0x3CB0000000000000
  %25 = fcmp ole double %22, %24
  %26 = zext i1 %25 to i32
  ret i32 %26
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_PrintUnformatted(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = call ptr @print(ptr noundef %3, i32 noundef 0, ptr noundef @global_hooks)
  ret ptr %4
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_PrintBuffered(ptr noundef %0, i32 noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca %struct.printbuffer, align 8
  store ptr %0, ptr %5, align 8
  store i32 %1, ptr %6, align 4
  store i32 %2, ptr %7, align 4
  call void @llvm.memset.p0.i64(ptr align 8 %8, i8 0, i64 64, i1 false)
  %9 = load i32, ptr %6, align 4
  %10 = icmp slt i32 %9, 0
  br i1 %10, label %11, label %12

11:                                               ; preds = %3
  store ptr null, ptr %4, align 8
  br label %42

12:                                               ; preds = %3
  %13 = load ptr, ptr @global_hooks, align 8
  %14 = load i32, ptr %6, align 4
  %15 = sext i32 %14 to i64
  %16 = call ptr %13(i64 noundef %15)
  %17 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 0
  store ptr %16, ptr %17, align 8
  %18 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 0
  %19 = load ptr, ptr %18, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %22, label %21

21:                                               ; preds = %12
  store ptr null, ptr %4, align 8
  br label %42

22:                                               ; preds = %12
  %23 = load i32, ptr %6, align 4
  %24 = sext i32 %23 to i64
  %25 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 1
  store i64 %24, ptr %25, align 8
  %26 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 2
  store i64 0, ptr %26, align 8
  %27 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 4
  store i32 0, ptr %27, align 8
  %28 = load i32, ptr %7, align 4
  %29 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 5
  store i32 %28, ptr %29, align 4
  %30 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 6
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %30, ptr align 8 @global_hooks, i64 24, i1 false)
  %31 = load ptr, ptr %5, align 8
  %32 = call i32 @print_value(ptr noundef %31, ptr noundef %8)
  %33 = icmp ne i32 %32, 0
  br i1 %33, label %39, label %34

34:                                               ; preds = %22
  %35 = load ptr, ptr getelementptr inbounds (%struct.internal_hooks, ptr @global_hooks, i32 0, i32 1), align 8
  %36 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 0
  %37 = load ptr, ptr %36, align 8
  call void %35(ptr noundef %37)
  %38 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 0
  store ptr null, ptr %38, align 8
  store ptr null, ptr %4, align 8
  br label %42

39:                                               ; preds = %22
  %40 = getelementptr inbounds %struct.printbuffer, ptr %8, i32 0, i32 0
  %41 = load ptr, ptr %40, align 8
  store ptr %41, ptr %4, align 8
  br label %42

42:                                               ; preds = %39, %34, %21, %11
  %43 = load ptr, ptr %4, align 8
  ret ptr %43
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_PrintPreallocated(ptr noundef %0, ptr noundef %1, i32 noundef %2, i32 noundef %3) #0 {
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca i32, align 4
  %9 = alloca i32, align 4
  %10 = alloca %struct.printbuffer, align 8
  store ptr %0, ptr %6, align 8
  store ptr %1, ptr %7, align 8
  store i32 %2, ptr %8, align 4
  store i32 %3, ptr %9, align 4
  call void @llvm.memset.p0.i64(ptr align 8 %10, i8 0, i64 64, i1 false)
  %11 = load i32, ptr %8, align 4
  %12 = icmp slt i32 %11, 0
  br i1 %12, label %16, label %13

13:                                               ; preds = %4
  %14 = load ptr, ptr %7, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %16, label %17

16:                                               ; preds = %13, %4
  store i32 0, ptr %5, align 4
  br label %30

17:                                               ; preds = %13
  %18 = load ptr, ptr %7, align 8
  %19 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 0
  store ptr %18, ptr %19, align 8
  %20 = load i32, ptr %8, align 4
  %21 = sext i32 %20 to i64
  %22 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 1
  store i64 %21, ptr %22, align 8
  %23 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 2
  store i64 0, ptr %23, align 8
  %24 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 4
  store i32 1, ptr %24, align 8
  %25 = load i32, ptr %9, align 4
  %26 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 5
  store i32 %25, ptr %26, align 4
  %27 = getelementptr inbounds %struct.printbuffer, ptr %10, i32 0, i32 6
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %27, ptr align 8 @global_hooks, i64 24, i1 false)
  %28 = load ptr, ptr %6, align 8
  %29 = call i32 @print_value(ptr noundef %28, ptr noundef %10)
  store i32 %29, ptr %5, align 4
  br label %30

30:                                               ; preds = %17, %16
  %31 = load i32, ptr %5, align 4
  ret i32 %31
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_GetArraySize(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  store ptr %0, ptr %3, align 8
  store ptr null, ptr %4, align 8
  store i64 0, ptr %5, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = icmp eq ptr %6, null
  br i1 %7, label %8, label %9

8:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %25

9:                                                ; preds = %1
  %10 = load ptr, ptr %3, align 8
  %11 = getelementptr inbounds %struct.cJSON, ptr %10, i32 0, i32 2
  %12 = load ptr, ptr %11, align 8
  store ptr %12, ptr %4, align 8
  br label %13

13:                                               ; preds = %16, %9
  %14 = load ptr, ptr %4, align 8
  %15 = icmp ne ptr %14, null
  br i1 %15, label %16, label %22

16:                                               ; preds = %13
  %17 = load i64, ptr %5, align 8
  %18 = add i64 %17, 1
  store i64 %18, ptr %5, align 8
  %19 = load ptr, ptr %4, align 8
  %20 = getelementptr inbounds %struct.cJSON, ptr %19, i32 0, i32 0
  %21 = load ptr, ptr %20, align 8
  store ptr %21, ptr %4, align 8
  br label %13, !llvm.loop !24

22:                                               ; preds = %13
  %23 = load i64, ptr %5, align 8
  %24 = trunc i64 %23 to i32
  store i32 %24, ptr %2, align 4
  br label %25

25:                                               ; preds = %22, %8
  %26 = load i32, ptr %2, align 4
  ret i32 %26
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_GetArrayItem(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  %6 = load i32, ptr %5, align 4
  %7 = icmp slt i32 %6, 0
  br i1 %7, label %8, label %9

8:                                                ; preds = %2
  store ptr null, ptr %3, align 8
  br label %14

9:                                                ; preds = %2
  %10 = load ptr, ptr %4, align 8
  %11 = load i32, ptr %5, align 4
  %12 = sext i32 %11 to i64
  %13 = call ptr @get_array_item(ptr noundef %10, i64 noundef %12)
  store ptr %13, ptr %3, align 8
  br label %14

14:                                               ; preds = %9, %8
  %15 = load ptr, ptr %3, align 8
  ret ptr %15
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @get_array_item(ptr noundef %0, i64 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = icmp eq ptr %7, null
  br i1 %8, label %9, label %10

9:                                                ; preds = %2
  store ptr null, ptr %3, align 8
  br label %30

10:                                               ; preds = %2
  %11 = load ptr, ptr %4, align 8
  %12 = getelementptr inbounds %struct.cJSON, ptr %11, i32 0, i32 2
  %13 = load ptr, ptr %12, align 8
  store ptr %13, ptr %6, align 8
  br label %14

14:                                               ; preds = %22, %10
  %15 = load ptr, ptr %6, align 8
  %16 = icmp ne ptr %15, null
  br i1 %16, label %17, label %20

17:                                               ; preds = %14
  %18 = load i64, ptr %5, align 8
  %19 = icmp ugt i64 %18, 0
  br label %20

20:                                               ; preds = %17, %14
  %21 = phi i1 [ false, %14 ], [ %19, %17 ]
  br i1 %21, label %22, label %28

22:                                               ; preds = %20
  %23 = load i64, ptr %5, align 8
  %24 = add i64 %23, -1
  store i64 %24, ptr %5, align 8
  %25 = load ptr, ptr %6, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 0
  %27 = load ptr, ptr %26, align 8
  store ptr %27, ptr %6, align 8
  br label %14, !llvm.loop !25

28:                                               ; preds = %20
  %29 = load ptr, ptr %6, align 8
  store ptr %29, ptr %3, align 8
  br label %30

30:                                               ; preds = %28, %9
  %31 = load ptr, ptr %3, align 8
  ret ptr %31
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_GetObjectItem(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @get_object_item(ptr noundef %5, ptr noundef %6, i32 noundef 0)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @get_object_item(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  store ptr null, ptr %8, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %14, label %11

11:                                               ; preds = %3
  %12 = load ptr, ptr %6, align 8
  %13 = icmp eq ptr %12, null
  br i1 %13, label %14, label %15

14:                                               ; preds = %11, %3
  store ptr null, ptr %4, align 8
  br label %73

15:                                               ; preds = %11
  %16 = load ptr, ptr %5, align 8
  %17 = getelementptr inbounds %struct.cJSON, ptr %16, i32 0, i32 2
  %18 = load ptr, ptr %17, align 8
  store ptr %18, ptr %8, align 8
  %19 = load i32, ptr %7, align 4
  %20 = icmp ne i32 %19, 0
  br i1 %20, label %21, label %44

21:                                               ; preds = %15
  br label %22

22:                                               ; preds = %39, %21
  %23 = load ptr, ptr %8, align 8
  %24 = icmp ne ptr %23, null
  br i1 %24, label %25, label %37

25:                                               ; preds = %22
  %26 = load ptr, ptr %8, align 8
  %27 = getelementptr inbounds %struct.cJSON, ptr %26, i32 0, i32 7
  %28 = load ptr, ptr %27, align 8
  %29 = icmp ne ptr %28, null
  br i1 %29, label %30, label %37

30:                                               ; preds = %25
  %31 = load ptr, ptr %6, align 8
  %32 = load ptr, ptr %8, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 7
  %34 = load ptr, ptr %33, align 8
  %35 = call i32 @strcmp(ptr noundef %31, ptr noundef %34) #9
  %36 = icmp ne i32 %35, 0
  br label %37

37:                                               ; preds = %30, %25, %22
  %38 = phi i1 [ false, %25 ], [ false, %22 ], [ %36, %30 ]
  br i1 %38, label %39, label %43

39:                                               ; preds = %37
  %40 = load ptr, ptr %8, align 8
  %41 = getelementptr inbounds %struct.cJSON, ptr %40, i32 0, i32 0
  %42 = load ptr, ptr %41, align 8
  store ptr %42, ptr %8, align 8
  br label %22, !llvm.loop !26

43:                                               ; preds = %37
  br label %62

44:                                               ; preds = %15
  br label %45

45:                                               ; preds = %57, %44
  %46 = load ptr, ptr %8, align 8
  %47 = icmp ne ptr %46, null
  br i1 %47, label %48, label %55

48:                                               ; preds = %45
  %49 = load ptr, ptr %6, align 8
  %50 = load ptr, ptr %8, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 7
  %52 = load ptr, ptr %51, align 8
  %53 = call i32 @case_insensitive_strcmp(ptr noundef %49, ptr noundef %52)
  %54 = icmp ne i32 %53, 0
  br label %55

55:                                               ; preds = %48, %45
  %56 = phi i1 [ false, %45 ], [ %54, %48 ]
  br i1 %56, label %57, label %61

57:                                               ; preds = %55
  %58 = load ptr, ptr %8, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 0
  %60 = load ptr, ptr %59, align 8
  store ptr %60, ptr %8, align 8
  br label %45, !llvm.loop !27

61:                                               ; preds = %55
  br label %62

62:                                               ; preds = %61, %43
  %63 = load ptr, ptr %8, align 8
  %64 = icmp eq ptr %63, null
  br i1 %64, label %70, label %65

65:                                               ; preds = %62
  %66 = load ptr, ptr %8, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 7
  %68 = load ptr, ptr %67, align 8
  %69 = icmp eq ptr %68, null
  br i1 %69, label %70, label %71

70:                                               ; preds = %65, %62
  store ptr null, ptr %4, align 8
  br label %73

71:                                               ; preds = %65
  %72 = load ptr, ptr %8, align 8
  store ptr %72, ptr %4, align 8
  br label %73

73:                                               ; preds = %71, %70, %14
  %74 = load ptr, ptr %4, align 8
  ret ptr %74
}

; Function Attrs: nounwind willreturn memory(read)
declare i32 @strcmp(ptr noundef, ptr noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @case_insensitive_strcmp(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp eq ptr %6, null
  br i1 %7, label %11, label %8

8:                                                ; preds = %2
  %9 = load ptr, ptr %5, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %11, label %12

11:                                               ; preds = %8, %2
  store i32 1, ptr %3, align 4
  br label %50

12:                                               ; preds = %8
  %13 = load ptr, ptr %4, align 8
  %14 = load ptr, ptr %5, align 8
  %15 = icmp eq ptr %13, %14
  br i1 %15, label %16, label %17

16:                                               ; preds = %12
  store i32 0, ptr %3, align 4
  br label %50

17:                                               ; preds = %12
  br label %18

18:                                               ; preds = %35, %17
  %19 = load ptr, ptr %4, align 8
  %20 = load i8, ptr %19, align 1
  %21 = zext i8 %20 to i32
  %22 = call i32 @tolower(i32 noundef %21) #9
  %23 = load ptr, ptr %5, align 8
  %24 = load i8, ptr %23, align 1
  %25 = zext i8 %24 to i32
  %26 = call i32 @tolower(i32 noundef %25) #9
  %27 = icmp eq i32 %22, %26
  br i1 %27, label %28, label %40

28:                                               ; preds = %18
  %29 = load ptr, ptr %4, align 8
  %30 = load i8, ptr %29, align 1
  %31 = zext i8 %30 to i32
  %32 = icmp eq i32 %31, 0
  br i1 %32, label %33, label %34

33:                                               ; preds = %28
  store i32 0, ptr %3, align 4
  br label %50

34:                                               ; preds = %28
  br label %35

35:                                               ; preds = %34
  %36 = load ptr, ptr %4, align 8
  %37 = getelementptr inbounds i8, ptr %36, i32 1
  store ptr %37, ptr %4, align 8
  %38 = load ptr, ptr %5, align 8
  %39 = getelementptr inbounds i8, ptr %38, i32 1
  store ptr %39, ptr %5, align 8
  br label %18, !llvm.loop !28

40:                                               ; preds = %18
  %41 = load ptr, ptr %4, align 8
  %42 = load i8, ptr %41, align 1
  %43 = zext i8 %42 to i32
  %44 = call i32 @tolower(i32 noundef %43) #9
  %45 = load ptr, ptr %5, align 8
  %46 = load i8, ptr %45, align 1
  %47 = zext i8 %46 to i32
  %48 = call i32 @tolower(i32 noundef %47) #9
  %49 = sub nsw i32 %44, %48
  store i32 %49, ptr %3, align 4
  br label %50

50:                                               ; preds = %40, %33, %16, %11
  %51 = load i32, ptr %3, align 4
  ret i32 %51
}

; Function Attrs: nounwind willreturn memory(read)
declare i32 @tolower(i32 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_GetObjectItemCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @get_object_item(ptr noundef %5, ptr noundef %6, i32 noundef 1)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_HasObjectItem(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @cJSON_GetObjectItem(ptr noundef %5, ptr noundef %6)
  %8 = icmp ne ptr %7, null
  %9 = zext i1 %8 to i64
  %10 = select i1 %8, i32 1, i32 0
  ret i32 %10
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_AddItemToArray(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call i32 @add_item_to_array(ptr noundef %5, ptr noundef %6)
  ret i32 %7
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @add_item_to_array(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %7 = load ptr, ptr %5, align 8
  %8 = icmp eq ptr %7, null
  br i1 %8, label %16, label %9

9:                                                ; preds = %2
  %10 = load ptr, ptr %4, align 8
  %11 = icmp eq ptr %10, null
  br i1 %11, label %16, label %12

12:                                               ; preds = %9
  %13 = load ptr, ptr %4, align 8
  %14 = load ptr, ptr %5, align 8
  %15 = icmp eq ptr %13, %14
  br i1 %15, label %16, label %17

16:                                               ; preds = %12, %9, %2
  store i32 0, ptr %3, align 4
  br label %49

17:                                               ; preds = %12
  %18 = load ptr, ptr %4, align 8
  %19 = getelementptr inbounds %struct.cJSON, ptr %18, i32 0, i32 2
  %20 = load ptr, ptr %19, align 8
  store ptr %20, ptr %6, align 8
  %21 = load ptr, ptr %6, align 8
  %22 = icmp eq ptr %21, null
  br i1 %22, label %23, label %32

23:                                               ; preds = %17
  %24 = load ptr, ptr %5, align 8
  %25 = load ptr, ptr %4, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 2
  store ptr %24, ptr %26, align 8
  %27 = load ptr, ptr %5, align 8
  %28 = load ptr, ptr %5, align 8
  %29 = getelementptr inbounds %struct.cJSON, ptr %28, i32 0, i32 1
  store ptr %27, ptr %29, align 8
  %30 = load ptr, ptr %5, align 8
  %31 = getelementptr inbounds %struct.cJSON, ptr %30, i32 0, i32 0
  store ptr null, ptr %31, align 8
  br label %48

32:                                               ; preds = %17
  %33 = load ptr, ptr %6, align 8
  %34 = getelementptr inbounds %struct.cJSON, ptr %33, i32 0, i32 1
  %35 = load ptr, ptr %34, align 8
  %36 = icmp ne ptr %35, null
  br i1 %36, label %37, label %47

37:                                               ; preds = %32
  %38 = load ptr, ptr %6, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 1
  %40 = load ptr, ptr %39, align 8
  %41 = load ptr, ptr %5, align 8
  call void @suffix_object(ptr noundef %40, ptr noundef %41)
  %42 = load ptr, ptr %5, align 8
  %43 = load ptr, ptr %4, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 2
  %45 = load ptr, ptr %44, align 8
  %46 = getelementptr inbounds %struct.cJSON, ptr %45, i32 0, i32 1
  store ptr %42, ptr %46, align 8
  br label %47

47:                                               ; preds = %37, %32
  br label %48

48:                                               ; preds = %47, %23
  store i32 1, ptr %3, align 4
  br label %49

49:                                               ; preds = %48, %16
  %50 = load i32, ptr %3, align 4
  ret i32 %50
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @suffix_object(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %4, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 0
  store ptr %5, ptr %7, align 8
  %8 = load ptr, ptr %3, align 8
  %9 = load ptr, ptr %4, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 1
  store ptr %8, ptr %10, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_AddItemToObject(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr %2, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = load ptr, ptr %6, align 8
  %10 = call i32 @add_item_to_object(ptr noundef %7, ptr noundef %8, ptr noundef %9, ptr noundef @global_hooks, i32 noundef 0)
  ret i32 %10
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @add_item_to_object(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, i32 noundef %4) #0 {
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca i32, align 4
  %12 = alloca ptr, align 8
  %13 = alloca i32, align 4
  store ptr %0, ptr %7, align 8
  store ptr %1, ptr %8, align 8
  store ptr %2, ptr %9, align 8
  store ptr %3, ptr %10, align 8
  store i32 %4, ptr %11, align 4
  store ptr null, ptr %12, align 8
  store i32 0, ptr %13, align 4
  %14 = load ptr, ptr %7, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %26, label %16

16:                                               ; preds = %5
  %17 = load ptr, ptr %8, align 8
  %18 = icmp eq ptr %17, null
  br i1 %18, label %26, label %19

19:                                               ; preds = %16
  %20 = load ptr, ptr %9, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %26, label %22

22:                                               ; preds = %19
  %23 = load ptr, ptr %7, align 8
  %24 = load ptr, ptr %9, align 8
  %25 = icmp eq ptr %23, %24
  br i1 %25, label %26, label %27

26:                                               ; preds = %22, %19, %16, %5
  store i32 0, ptr %6, align 4
  br label %77

27:                                               ; preds = %22
  %28 = load i32, ptr %11, align 4
  %29 = icmp ne i32 %28, 0
  br i1 %29, label %30, label %37

30:                                               ; preds = %27
  %31 = load ptr, ptr %8, align 8
  %32 = call ptr @cast_away_const(ptr noundef %31)
  store ptr %32, ptr %12, align 8
  %33 = load ptr, ptr %9, align 8
  %34 = getelementptr inbounds %struct.cJSON, ptr %33, i32 0, i32 3
  %35 = load i32, ptr %34, align 8
  %36 = or i32 %35, 512
  store i32 %36, ptr %13, align 4
  br label %49

37:                                               ; preds = %27
  %38 = load ptr, ptr %8, align 8
  %39 = load ptr, ptr %10, align 8
  %40 = call ptr @cJSON_strdup(ptr noundef %38, ptr noundef %39)
  store ptr %40, ptr %12, align 8
  %41 = load ptr, ptr %12, align 8
  %42 = icmp eq ptr %41, null
  br i1 %42, label %43, label %44

43:                                               ; preds = %37
  store i32 0, ptr %6, align 4
  br label %77

44:                                               ; preds = %37
  %45 = load ptr, ptr %9, align 8
  %46 = getelementptr inbounds %struct.cJSON, ptr %45, i32 0, i32 3
  %47 = load i32, ptr %46, align 8
  %48 = and i32 %47, -513
  store i32 %48, ptr %13, align 4
  br label %49

49:                                               ; preds = %44, %30
  %50 = load ptr, ptr %9, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 3
  %52 = load i32, ptr %51, align 8
  %53 = and i32 %52, 512
  %54 = icmp ne i32 %53, 0
  br i1 %54, label %67, label %55

55:                                               ; preds = %49
  %56 = load ptr, ptr %9, align 8
  %57 = getelementptr inbounds %struct.cJSON, ptr %56, i32 0, i32 7
  %58 = load ptr, ptr %57, align 8
  %59 = icmp ne ptr %58, null
  br i1 %59, label %60, label %67

60:                                               ; preds = %55
  %61 = load ptr, ptr %10, align 8
  %62 = getelementptr inbounds %struct.internal_hooks, ptr %61, i32 0, i32 1
  %63 = load ptr, ptr %62, align 8
  %64 = load ptr, ptr %9, align 8
  %65 = getelementptr inbounds %struct.cJSON, ptr %64, i32 0, i32 7
  %66 = load ptr, ptr %65, align 8
  call void %63(ptr noundef %66)
  br label %67

67:                                               ; preds = %60, %55, %49
  %68 = load ptr, ptr %12, align 8
  %69 = load ptr, ptr %9, align 8
  %70 = getelementptr inbounds %struct.cJSON, ptr %69, i32 0, i32 7
  store ptr %68, ptr %70, align 8
  %71 = load i32, ptr %13, align 4
  %72 = load ptr, ptr %9, align 8
  %73 = getelementptr inbounds %struct.cJSON, ptr %72, i32 0, i32 3
  store i32 %71, ptr %73, align 8
  %74 = load ptr, ptr %7, align 8
  %75 = load ptr, ptr %9, align 8
  %76 = call i32 @add_item_to_array(ptr noundef %74, ptr noundef %75)
  store i32 %76, ptr %6, align 4
  br label %77

77:                                               ; preds = %67, %43, %26
  %78 = load i32, ptr %6, align 4
  ret i32 %78
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @cast_away_const(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  ret ptr %3
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_AddItemToObjectCS(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr %2, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = load ptr, ptr %6, align 8
  %10 = call i32 @add_item_to_object(ptr noundef %7, ptr noundef %8, ptr noundef %9, ptr noundef @global_hooks, i32 noundef 1)
  ret i32 %10
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_AddItemReferenceToArray(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp eq ptr %6, null
  br i1 %7, label %8, label %9

8:                                                ; preds = %2
  store i32 0, ptr %3, align 4
  br label %14

9:                                                ; preds = %2
  %10 = load ptr, ptr %4, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = call ptr @create_reference(ptr noundef %11, ptr noundef @global_hooks)
  %13 = call i32 @add_item_to_array(ptr noundef %10, ptr noundef %12)
  store i32 %13, ptr %3, align 4
  br label %14

14:                                               ; preds = %9, %8
  %15 = load i32, ptr %3, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @create_reference(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = icmp eq ptr %7, null
  br i1 %8, label %9, label %10

9:                                                ; preds = %2
  store ptr null, ptr %3, align 8
  br label %30

10:                                               ; preds = %2
  %11 = load ptr, ptr %5, align 8
  %12 = call ptr @cJSON_New_Item(ptr noundef %11)
  store ptr %12, ptr %6, align 8
  %13 = load ptr, ptr %6, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %10
  store ptr null, ptr %3, align 8
  br label %30

16:                                               ; preds = %10
  %17 = load ptr, ptr %6, align 8
  %18 = load ptr, ptr %4, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %17, ptr align 8 %18, i64 64, i1 false)
  %19 = load ptr, ptr %6, align 8
  %20 = getelementptr inbounds %struct.cJSON, ptr %19, i32 0, i32 7
  store ptr null, ptr %20, align 8
  %21 = load ptr, ptr %6, align 8
  %22 = getelementptr inbounds %struct.cJSON, ptr %21, i32 0, i32 3
  %23 = load i32, ptr %22, align 8
  %24 = or i32 %23, 256
  store i32 %24, ptr %22, align 8
  %25 = load ptr, ptr %6, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 1
  store ptr null, ptr %26, align 8
  %27 = load ptr, ptr %6, align 8
  %28 = getelementptr inbounds %struct.cJSON, ptr %27, i32 0, i32 0
  store ptr null, ptr %28, align 8
  %29 = load ptr, ptr %6, align 8
  store ptr %29, ptr %3, align 8
  br label %30

30:                                               ; preds = %16, %15, %9
  %31 = load ptr, ptr %3, align 8
  ret ptr %31
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_AddItemReferenceToObject(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %13, label %10

10:                                               ; preds = %3
  %11 = load ptr, ptr %6, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %10, %3
  store i32 0, ptr %4, align 4
  br label %20

14:                                               ; preds = %10
  %15 = load ptr, ptr %5, align 8
  %16 = load ptr, ptr %6, align 8
  %17 = load ptr, ptr %7, align 8
  %18 = call ptr @create_reference(ptr noundef %17, ptr noundef @global_hooks)
  %19 = call i32 @add_item_to_object(ptr noundef %15, ptr noundef %16, ptr noundef %18, ptr noundef @global_hooks, i32 noundef 0)
  store i32 %19, ptr %4, align 4
  br label %20

20:                                               ; preds = %14, %13
  %21 = load i32, ptr %4, align 4
  ret i32 %21
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddNullToObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %7 = call ptr @cJSON_CreateNull()
  store ptr %7, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @add_item_to_object(ptr noundef %8, ptr noundef %9, ptr noundef %10, ptr noundef @global_hooks, i32 noundef 0)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %15

13:                                               ; preds = %2
  %14 = load ptr, ptr %6, align 8
  store ptr %14, ptr %3, align 8
  br label %17

15:                                               ; preds = %2
  %16 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %16)
  store ptr null, ptr %3, align 8
  br label %17

17:                                               ; preds = %15, %13
  %18 = load ptr, ptr %3, align 8
  ret ptr %18
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateNull() #0 {
  %1 = alloca ptr, align 8
  %2 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %8

5:                                                ; preds = %0
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 3
  store i32 4, ptr %7, align 8
  br label %8

8:                                                ; preds = %5, %0
  %9 = load ptr, ptr %1, align 8
  ret ptr %9
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddTrueToObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %7 = call ptr @cJSON_CreateTrue()
  store ptr %7, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @add_item_to_object(ptr noundef %8, ptr noundef %9, ptr noundef %10, ptr noundef @global_hooks, i32 noundef 0)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %15

13:                                               ; preds = %2
  %14 = load ptr, ptr %6, align 8
  store ptr %14, ptr %3, align 8
  br label %17

15:                                               ; preds = %2
  %16 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %16)
  store ptr null, ptr %3, align 8
  br label %17

17:                                               ; preds = %15, %13
  %18 = load ptr, ptr %3, align 8
  ret ptr %18
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateTrue() #0 {
  %1 = alloca ptr, align 8
  %2 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %8

5:                                                ; preds = %0
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 3
  store i32 2, ptr %7, align 8
  br label %8

8:                                                ; preds = %5, %0
  %9 = load ptr, ptr %1, align 8
  ret ptr %9
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddFalseToObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %7 = call ptr @cJSON_CreateFalse()
  store ptr %7, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @add_item_to_object(ptr noundef %8, ptr noundef %9, ptr noundef %10, ptr noundef @global_hooks, i32 noundef 0)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %15

13:                                               ; preds = %2
  %14 = load ptr, ptr %6, align 8
  store ptr %14, ptr %3, align 8
  br label %17

15:                                               ; preds = %2
  %16 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %16)
  store ptr null, ptr %3, align 8
  br label %17

17:                                               ; preds = %15, %13
  %18 = load ptr, ptr %3, align 8
  ret ptr %18
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateFalse() #0 {
  %1 = alloca ptr, align 8
  %2 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %8

5:                                                ; preds = %0
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 3
  store i32 1, ptr %7, align 8
  br label %8

8:                                                ; preds = %5, %0
  %9 = load ptr, ptr %1, align 8
  ret ptr %9
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddBoolToObject(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %9 = load i32, ptr %7, align 4
  %10 = call ptr @cJSON_CreateBool(i32 noundef %9)
  store ptr %10, ptr %8, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = load ptr, ptr %8, align 8
  %14 = call i32 @add_item_to_object(ptr noundef %11, ptr noundef %12, ptr noundef %13, ptr noundef @global_hooks, i32 noundef 0)
  %15 = icmp ne i32 %14, 0
  br i1 %15, label %16, label %18

16:                                               ; preds = %3
  %17 = load ptr, ptr %8, align 8
  store ptr %17, ptr %4, align 8
  br label %20

18:                                               ; preds = %3
  %19 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %19)
  store ptr null, ptr %4, align 8
  br label %20

20:                                               ; preds = %18, %16
  %21 = load ptr, ptr %4, align 8
  ret ptr %21
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateBool(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store i32 %0, ptr %2, align 4
  %4 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %14

7:                                                ; preds = %1
  %8 = load i32, ptr %2, align 4
  %9 = icmp ne i32 %8, 0
  %10 = zext i1 %9 to i64
  %11 = select i1 %9, i32 2, i32 1
  %12 = load ptr, ptr %3, align 8
  %13 = getelementptr inbounds %struct.cJSON, ptr %12, i32 0, i32 3
  store i32 %11, ptr %13, align 8
  br label %14

14:                                               ; preds = %7, %1
  %15 = load ptr, ptr %3, align 8
  ret ptr %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddNumberToObject(ptr noundef %0, ptr noundef %1, double noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca double, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store double %2, ptr %7, align 8
  %9 = load double, ptr %7, align 8
  %10 = call ptr @cJSON_CreateNumber(double noundef %9)
  store ptr %10, ptr %8, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = load ptr, ptr %8, align 8
  %14 = call i32 @add_item_to_object(ptr noundef %11, ptr noundef %12, ptr noundef %13, ptr noundef @global_hooks, i32 noundef 0)
  %15 = icmp ne i32 %14, 0
  br i1 %15, label %16, label %18

16:                                               ; preds = %3
  %17 = load ptr, ptr %8, align 8
  store ptr %17, ptr %4, align 8
  br label %20

18:                                               ; preds = %3
  %19 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %19)
  store ptr null, ptr %4, align 8
  br label %20

20:                                               ; preds = %18, %16
  %21 = load ptr, ptr %4, align 8
  ret ptr %21
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateNumber(double noundef %0) #0 {
  %2 = alloca double, align 8
  %3 = alloca ptr, align 8
  store double %0, ptr %2, align 8
  %4 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %31

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  store i32 8, ptr %9, align 8
  %10 = load double, ptr %2, align 8
  %11 = load ptr, ptr %3, align 8
  %12 = getelementptr inbounds %struct.cJSON, ptr %11, i32 0, i32 6
  store double %10, ptr %12, align 8
  %13 = load double, ptr %2, align 8
  %14 = fcmp oge double %13, 0x41DFFFFFFFC00000
  br i1 %14, label %15, label %18

15:                                               ; preds = %7
  %16 = load ptr, ptr %3, align 8
  %17 = getelementptr inbounds %struct.cJSON, ptr %16, i32 0, i32 5
  store i32 2147483647, ptr %17, align 8
  br label %30

18:                                               ; preds = %7
  %19 = load double, ptr %2, align 8
  %20 = fcmp ole double %19, 0xC1E0000000000000
  br i1 %20, label %21, label %24

21:                                               ; preds = %18
  %22 = load ptr, ptr %3, align 8
  %23 = getelementptr inbounds %struct.cJSON, ptr %22, i32 0, i32 5
  store i32 -2147483648, ptr %23, align 8
  br label %29

24:                                               ; preds = %18
  %25 = load double, ptr %2, align 8
  %26 = fptosi double %25 to i32
  %27 = load ptr, ptr %3, align 8
  %28 = getelementptr inbounds %struct.cJSON, ptr %27, i32 0, i32 5
  store i32 %26, ptr %28, align 8
  br label %29

29:                                               ; preds = %24, %21
  br label %30

30:                                               ; preds = %29, %15
  br label %31

31:                                               ; preds = %30, %1
  %32 = load ptr, ptr %3, align 8
  ret ptr %32
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddStringToObject(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  %9 = load ptr, ptr %7, align 8
  %10 = call ptr @cJSON_CreateString(ptr noundef %9)
  store ptr %10, ptr %8, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = load ptr, ptr %8, align 8
  %14 = call i32 @add_item_to_object(ptr noundef %11, ptr noundef %12, ptr noundef %13, ptr noundef @global_hooks, i32 noundef 0)
  %15 = icmp ne i32 %14, 0
  br i1 %15, label %16, label %18

16:                                               ; preds = %3
  %17 = load ptr, ptr %8, align 8
  store ptr %17, ptr %4, align 8
  br label %20

18:                                               ; preds = %3
  %19 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %19)
  store ptr null, ptr %4, align 8
  br label %20

20:                                               ; preds = %18, %16
  %21 = load ptr, ptr %4, align 8
  ret ptr %21
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateString(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %5 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %5, ptr %4, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp ne ptr %6, null
  br i1 %7, label %8, label %22

8:                                                ; preds = %1
  %9 = load ptr, ptr %4, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 3
  store i32 16, ptr %10, align 8
  %11 = load ptr, ptr %3, align 8
  %12 = call ptr @cJSON_strdup(ptr noundef %11, ptr noundef @global_hooks)
  %13 = load ptr, ptr %4, align 8
  %14 = getelementptr inbounds %struct.cJSON, ptr %13, i32 0, i32 4
  store ptr %12, ptr %14, align 8
  %15 = load ptr, ptr %4, align 8
  %16 = getelementptr inbounds %struct.cJSON, ptr %15, i32 0, i32 4
  %17 = load ptr, ptr %16, align 8
  %18 = icmp ne ptr %17, null
  br i1 %18, label %21, label %19

19:                                               ; preds = %8
  %20 = load ptr, ptr %4, align 8
  call void @cJSON_Delete(ptr noundef %20)
  store ptr null, ptr %2, align 8
  br label %24

21:                                               ; preds = %8
  br label %22

22:                                               ; preds = %21, %1
  %23 = load ptr, ptr %4, align 8
  store ptr %23, ptr %2, align 8
  br label %24

24:                                               ; preds = %22, %19
  %25 = load ptr, ptr %2, align 8
  ret ptr %25
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddRawToObject(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  %9 = load ptr, ptr %7, align 8
  %10 = call ptr @cJSON_CreateRaw(ptr noundef %9)
  store ptr %10, ptr %8, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = load ptr, ptr %8, align 8
  %14 = call i32 @add_item_to_object(ptr noundef %11, ptr noundef %12, ptr noundef %13, ptr noundef @global_hooks, i32 noundef 0)
  %15 = icmp ne i32 %14, 0
  br i1 %15, label %16, label %18

16:                                               ; preds = %3
  %17 = load ptr, ptr %8, align 8
  store ptr %17, ptr %4, align 8
  br label %20

18:                                               ; preds = %3
  %19 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %19)
  store ptr null, ptr %4, align 8
  br label %20

20:                                               ; preds = %18, %16
  %21 = load ptr, ptr %4, align 8
  ret ptr %21
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateRaw(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %5 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %5, ptr %4, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp ne ptr %6, null
  br i1 %7, label %8, label %22

8:                                                ; preds = %1
  %9 = load ptr, ptr %4, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 3
  store i32 128, ptr %10, align 8
  %11 = load ptr, ptr %3, align 8
  %12 = call ptr @cJSON_strdup(ptr noundef %11, ptr noundef @global_hooks)
  %13 = load ptr, ptr %4, align 8
  %14 = getelementptr inbounds %struct.cJSON, ptr %13, i32 0, i32 4
  store ptr %12, ptr %14, align 8
  %15 = load ptr, ptr %4, align 8
  %16 = getelementptr inbounds %struct.cJSON, ptr %15, i32 0, i32 4
  %17 = load ptr, ptr %16, align 8
  %18 = icmp ne ptr %17, null
  br i1 %18, label %21, label %19

19:                                               ; preds = %8
  %20 = load ptr, ptr %4, align 8
  call void @cJSON_Delete(ptr noundef %20)
  store ptr null, ptr %2, align 8
  br label %24

21:                                               ; preds = %8
  br label %22

22:                                               ; preds = %21, %1
  %23 = load ptr, ptr %4, align 8
  store ptr %23, ptr %2, align 8
  br label %24

24:                                               ; preds = %22, %19
  %25 = load ptr, ptr %2, align 8
  ret ptr %25
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddObjectToObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %7 = call ptr @cJSON_CreateObject()
  store ptr %7, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @add_item_to_object(ptr noundef %8, ptr noundef %9, ptr noundef %10, ptr noundef @global_hooks, i32 noundef 0)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %15

13:                                               ; preds = %2
  %14 = load ptr, ptr %6, align 8
  store ptr %14, ptr %3, align 8
  br label %17

15:                                               ; preds = %2
  %16 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %16)
  store ptr null, ptr %3, align 8
  br label %17

17:                                               ; preds = %15, %13
  %18 = load ptr, ptr %3, align 8
  ret ptr %18
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateObject() #0 {
  %1 = alloca ptr, align 8
  %2 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %8

5:                                                ; preds = %0
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 3
  store i32 64, ptr %7, align 8
  br label %8

8:                                                ; preds = %5, %0
  %9 = load ptr, ptr %1, align 8
  ret ptr %9
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_AddArrayToObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %7 = call ptr @cJSON_CreateArray()
  store ptr %7, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @add_item_to_object(ptr noundef %8, ptr noundef %9, ptr noundef %10, ptr noundef @global_hooks, i32 noundef 0)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %15

13:                                               ; preds = %2
  %14 = load ptr, ptr %6, align 8
  store ptr %14, ptr %3, align 8
  br label %17

15:                                               ; preds = %2
  %16 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %16)
  store ptr null, ptr %3, align 8
  br label %17

17:                                               ; preds = %15, %13
  %18 = load ptr, ptr %3, align 8
  ret ptr %18
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateArray() #0 {
  %1 = alloca ptr, align 8
  %2 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = icmp ne ptr %3, null
  br i1 %4, label %5, label %8

5:                                                ; preds = %0
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds %struct.cJSON, ptr %6, i32 0, i32 3
  store i32 32, ptr %7, align 8
  br label %8

8:                                                ; preds = %5, %0
  %9 = load ptr, ptr %1, align 8
  ret ptr %9
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_DetachItemViaPointer(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = icmp eq ptr %6, null
  br i1 %7, label %22, label %8

8:                                                ; preds = %2
  %9 = load ptr, ptr %5, align 8
  %10 = icmp eq ptr %9, null
  br i1 %10, label %22, label %11

11:                                               ; preds = %8
  %12 = load ptr, ptr %5, align 8
  %13 = load ptr, ptr %4, align 8
  %14 = getelementptr inbounds %struct.cJSON, ptr %13, i32 0, i32 2
  %15 = load ptr, ptr %14, align 8
  %16 = icmp ne ptr %12, %15
  br i1 %16, label %17, label %23

17:                                               ; preds = %11
  %18 = load ptr, ptr %5, align 8
  %19 = getelementptr inbounds %struct.cJSON, ptr %18, i32 0, i32 1
  %20 = load ptr, ptr %19, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %22, label %23

22:                                               ; preds = %17, %8, %2
  store ptr null, ptr %3, align 8
  br label %82

23:                                               ; preds = %17, %11
  %24 = load ptr, ptr %5, align 8
  %25 = load ptr, ptr %4, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 2
  %27 = load ptr, ptr %26, align 8
  %28 = icmp ne ptr %24, %27
  br i1 %28, label %29, label %37

29:                                               ; preds = %23
  %30 = load ptr, ptr %5, align 8
  %31 = getelementptr inbounds %struct.cJSON, ptr %30, i32 0, i32 0
  %32 = load ptr, ptr %31, align 8
  %33 = load ptr, ptr %5, align 8
  %34 = getelementptr inbounds %struct.cJSON, ptr %33, i32 0, i32 1
  %35 = load ptr, ptr %34, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 0
  store ptr %32, ptr %36, align 8
  br label %37

37:                                               ; preds = %29, %23
  %38 = load ptr, ptr %5, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 0
  %40 = load ptr, ptr %39, align 8
  %41 = icmp ne ptr %40, null
  br i1 %41, label %42, label %50

42:                                               ; preds = %37
  %43 = load ptr, ptr %5, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 1
  %45 = load ptr, ptr %44, align 8
  %46 = load ptr, ptr %5, align 8
  %47 = getelementptr inbounds %struct.cJSON, ptr %46, i32 0, i32 0
  %48 = load ptr, ptr %47, align 8
  %49 = getelementptr inbounds %struct.cJSON, ptr %48, i32 0, i32 1
  store ptr %45, ptr %49, align 8
  br label %50

50:                                               ; preds = %42, %37
  %51 = load ptr, ptr %5, align 8
  %52 = load ptr, ptr %4, align 8
  %53 = getelementptr inbounds %struct.cJSON, ptr %52, i32 0, i32 2
  %54 = load ptr, ptr %53, align 8
  %55 = icmp eq ptr %51, %54
  br i1 %55, label %56, label %62

56:                                               ; preds = %50
  %57 = load ptr, ptr %5, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 0
  %59 = load ptr, ptr %58, align 8
  %60 = load ptr, ptr %4, align 8
  %61 = getelementptr inbounds %struct.cJSON, ptr %60, i32 0, i32 2
  store ptr %59, ptr %61, align 8
  br label %76

62:                                               ; preds = %50
  %63 = load ptr, ptr %5, align 8
  %64 = getelementptr inbounds %struct.cJSON, ptr %63, i32 0, i32 0
  %65 = load ptr, ptr %64, align 8
  %66 = icmp eq ptr %65, null
  br i1 %66, label %67, label %75

67:                                               ; preds = %62
  %68 = load ptr, ptr %5, align 8
  %69 = getelementptr inbounds %struct.cJSON, ptr %68, i32 0, i32 1
  %70 = load ptr, ptr %69, align 8
  %71 = load ptr, ptr %4, align 8
  %72 = getelementptr inbounds %struct.cJSON, ptr %71, i32 0, i32 2
  %73 = load ptr, ptr %72, align 8
  %74 = getelementptr inbounds %struct.cJSON, ptr %73, i32 0, i32 1
  store ptr %70, ptr %74, align 8
  br label %75

75:                                               ; preds = %67, %62
  br label %76

76:                                               ; preds = %75, %56
  %77 = load ptr, ptr %5, align 8
  %78 = getelementptr inbounds %struct.cJSON, ptr %77, i32 0, i32 1
  store ptr null, ptr %78, align 8
  %79 = load ptr, ptr %5, align 8
  %80 = getelementptr inbounds %struct.cJSON, ptr %79, i32 0, i32 0
  store ptr null, ptr %80, align 8
  %81 = load ptr, ptr %5, align 8
  store ptr %81, ptr %3, align 8
  br label %82

82:                                               ; preds = %76, %22
  %83 = load ptr, ptr %3, align 8
  ret ptr %83
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_DetachItemFromArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  %6 = load i32, ptr %5, align 4
  %7 = icmp slt i32 %6, 0
  br i1 %7, label %8, label %9

8:                                                ; preds = %2
  store ptr null, ptr %3, align 8
  br label %16

9:                                                ; preds = %2
  %10 = load ptr, ptr %4, align 8
  %11 = load ptr, ptr %4, align 8
  %12 = load i32, ptr %5, align 4
  %13 = sext i32 %12 to i64
  %14 = call ptr @get_array_item(ptr noundef %11, i64 noundef %13)
  %15 = call ptr @cJSON_DetachItemViaPointer(ptr noundef %10, ptr noundef %14)
  store ptr %15, ptr %3, align 8
  br label %16

16:                                               ; preds = %9, %8
  %17 = load ptr, ptr %3, align 8
  ret ptr %17
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_DeleteItemFromArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store i32 %1, ptr %4, align 4
  %5 = load ptr, ptr %3, align 8
  %6 = load i32, ptr %4, align 4
  %7 = call ptr @cJSON_DetachItemFromArray(ptr noundef %5, i32 noundef %6)
  call void @cJSON_Delete(ptr noundef %7)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_DetachItemFromObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = call ptr @cJSON_GetObjectItem(ptr noundef %6, ptr noundef %7)
  store ptr %8, ptr %5, align 8
  %9 = load ptr, ptr %3, align 8
  %10 = load ptr, ptr %5, align 8
  %11 = call ptr @cJSON_DetachItemViaPointer(ptr noundef %9, ptr noundef %10)
  ret ptr %11
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_DetachItemFromObjectCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = call ptr @cJSON_GetObjectItemCaseSensitive(ptr noundef %6, ptr noundef %7)
  store ptr %8, ptr %5, align 8
  %9 = load ptr, ptr %3, align 8
  %10 = load ptr, ptr %5, align 8
  %11 = call ptr @cJSON_DetachItemViaPointer(ptr noundef %9, ptr noundef %10)
  ret ptr %11
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_DeleteItemFromObject(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @cJSON_DetachItemFromObject(ptr noundef %5, ptr noundef %6)
  call void @cJSON_Delete(ptr noundef %7)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_DeleteItemFromObjectCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @cJSON_DetachItemFromObjectCaseSensitive(ptr noundef %5, ptr noundef %6)
  call void @cJSON_Delete(ptr noundef %7)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_InsertItemInArray(ptr noundef %0, i32 noundef %1, ptr noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store i32 %1, ptr %6, align 4
  store ptr %2, ptr %7, align 8
  store ptr null, ptr %8, align 8
  %9 = load i32, ptr %6, align 4
  %10 = icmp slt i32 %9, 0
  br i1 %10, label %14, label %11

11:                                               ; preds = %3
  %12 = load ptr, ptr %7, align 8
  %13 = icmp eq ptr %12, null
  br i1 %13, label %14, label %15

14:                                               ; preds = %11, %3
  store i32 0, ptr %4, align 4
  br label %66

15:                                               ; preds = %11
  %16 = load ptr, ptr %5, align 8
  %17 = load i32, ptr %6, align 4
  %18 = sext i32 %17 to i64
  %19 = call ptr @get_array_item(ptr noundef %16, i64 noundef %18)
  store ptr %19, ptr %8, align 8
  %20 = load ptr, ptr %8, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %22, label %26

22:                                               ; preds = %15
  %23 = load ptr, ptr %5, align 8
  %24 = load ptr, ptr %7, align 8
  %25 = call i32 @add_item_to_array(ptr noundef %23, ptr noundef %24)
  store i32 %25, ptr %4, align 4
  br label %66

26:                                               ; preds = %15
  %27 = load ptr, ptr %8, align 8
  %28 = load ptr, ptr %5, align 8
  %29 = getelementptr inbounds %struct.cJSON, ptr %28, i32 0, i32 2
  %30 = load ptr, ptr %29, align 8
  %31 = icmp ne ptr %27, %30
  br i1 %31, label %32, label %38

32:                                               ; preds = %26
  %33 = load ptr, ptr %8, align 8
  %34 = getelementptr inbounds %struct.cJSON, ptr %33, i32 0, i32 1
  %35 = load ptr, ptr %34, align 8
  %36 = icmp eq ptr %35, null
  br i1 %36, label %37, label %38

37:                                               ; preds = %32
  store i32 0, ptr %4, align 4
  br label %66

38:                                               ; preds = %32, %26
  %39 = load ptr, ptr %8, align 8
  %40 = load ptr, ptr %7, align 8
  %41 = getelementptr inbounds %struct.cJSON, ptr %40, i32 0, i32 0
  store ptr %39, ptr %41, align 8
  %42 = load ptr, ptr %8, align 8
  %43 = getelementptr inbounds %struct.cJSON, ptr %42, i32 0, i32 1
  %44 = load ptr, ptr %43, align 8
  %45 = load ptr, ptr %7, align 8
  %46 = getelementptr inbounds %struct.cJSON, ptr %45, i32 0, i32 1
  store ptr %44, ptr %46, align 8
  %47 = load ptr, ptr %7, align 8
  %48 = load ptr, ptr %8, align 8
  %49 = getelementptr inbounds %struct.cJSON, ptr %48, i32 0, i32 1
  store ptr %47, ptr %49, align 8
  %50 = load ptr, ptr %8, align 8
  %51 = load ptr, ptr %5, align 8
  %52 = getelementptr inbounds %struct.cJSON, ptr %51, i32 0, i32 2
  %53 = load ptr, ptr %52, align 8
  %54 = icmp eq ptr %50, %53
  br i1 %54, label %55, label %59

55:                                               ; preds = %38
  %56 = load ptr, ptr %7, align 8
  %57 = load ptr, ptr %5, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 2
  store ptr %56, ptr %58, align 8
  br label %65

59:                                               ; preds = %38
  %60 = load ptr, ptr %7, align 8
  %61 = load ptr, ptr %7, align 8
  %62 = getelementptr inbounds %struct.cJSON, ptr %61, i32 0, i32 1
  %63 = load ptr, ptr %62, align 8
  %64 = getelementptr inbounds %struct.cJSON, ptr %63, i32 0, i32 0
  store ptr %60, ptr %64, align 8
  br label %65

65:                                               ; preds = %59, %55
  store i32 1, ptr %4, align 4
  br label %66

66:                                               ; preds = %65, %37, %22, %14
  %67 = load i32, ptr %4, align 4
  ret i32 %67
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_ReplaceItemViaPointer(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %21, label %10

10:                                               ; preds = %3
  %11 = load ptr, ptr %5, align 8
  %12 = getelementptr inbounds %struct.cJSON, ptr %11, i32 0, i32 2
  %13 = load ptr, ptr %12, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %21, label %15

15:                                               ; preds = %10
  %16 = load ptr, ptr %7, align 8
  %17 = icmp eq ptr %16, null
  br i1 %17, label %21, label %18

18:                                               ; preds = %15
  %19 = load ptr, ptr %6, align 8
  %20 = icmp eq ptr %19, null
  br i1 %20, label %21, label %22

21:                                               ; preds = %18, %15, %10, %3
  store i32 0, ptr %4, align 4
  br label %101

22:                                               ; preds = %18
  %23 = load ptr, ptr %7, align 8
  %24 = load ptr, ptr %6, align 8
  %25 = icmp eq ptr %23, %24
  br i1 %25, label %26, label %27

26:                                               ; preds = %22
  store i32 1, ptr %4, align 4
  br label %101

27:                                               ; preds = %22
  %28 = load ptr, ptr %6, align 8
  %29 = getelementptr inbounds %struct.cJSON, ptr %28, i32 0, i32 0
  %30 = load ptr, ptr %29, align 8
  %31 = load ptr, ptr %7, align 8
  %32 = getelementptr inbounds %struct.cJSON, ptr %31, i32 0, i32 0
  store ptr %30, ptr %32, align 8
  %33 = load ptr, ptr %6, align 8
  %34 = getelementptr inbounds %struct.cJSON, ptr %33, i32 0, i32 1
  %35 = load ptr, ptr %34, align 8
  %36 = load ptr, ptr %7, align 8
  %37 = getelementptr inbounds %struct.cJSON, ptr %36, i32 0, i32 1
  store ptr %35, ptr %37, align 8
  %38 = load ptr, ptr %7, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 0
  %40 = load ptr, ptr %39, align 8
  %41 = icmp ne ptr %40, null
  br i1 %41, label %42, label %48

42:                                               ; preds = %27
  %43 = load ptr, ptr %7, align 8
  %44 = load ptr, ptr %7, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 0
  %46 = load ptr, ptr %45, align 8
  %47 = getelementptr inbounds %struct.cJSON, ptr %46, i32 0, i32 1
  store ptr %43, ptr %47, align 8
  br label %48

48:                                               ; preds = %42, %27
  %49 = load ptr, ptr %5, align 8
  %50 = getelementptr inbounds %struct.cJSON, ptr %49, i32 0, i32 2
  %51 = load ptr, ptr %50, align 8
  %52 = load ptr, ptr %6, align 8
  %53 = icmp eq ptr %51, %52
  br i1 %53, label %54, label %72

54:                                               ; preds = %48
  %55 = load ptr, ptr %5, align 8
  %56 = getelementptr inbounds %struct.cJSON, ptr %55, i32 0, i32 2
  %57 = load ptr, ptr %56, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 1
  %59 = load ptr, ptr %58, align 8
  %60 = load ptr, ptr %5, align 8
  %61 = getelementptr inbounds %struct.cJSON, ptr %60, i32 0, i32 2
  %62 = load ptr, ptr %61, align 8
  %63 = icmp eq ptr %59, %62
  br i1 %63, label %64, label %68

64:                                               ; preds = %54
  %65 = load ptr, ptr %7, align 8
  %66 = load ptr, ptr %7, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 1
  store ptr %65, ptr %67, align 8
  br label %68

68:                                               ; preds = %64, %54
  %69 = load ptr, ptr %7, align 8
  %70 = load ptr, ptr %5, align 8
  %71 = getelementptr inbounds %struct.cJSON, ptr %70, i32 0, i32 2
  store ptr %69, ptr %71, align 8
  br label %95

72:                                               ; preds = %48
  %73 = load ptr, ptr %7, align 8
  %74 = getelementptr inbounds %struct.cJSON, ptr %73, i32 0, i32 1
  %75 = load ptr, ptr %74, align 8
  %76 = icmp ne ptr %75, null
  br i1 %76, label %77, label %83

77:                                               ; preds = %72
  %78 = load ptr, ptr %7, align 8
  %79 = load ptr, ptr %7, align 8
  %80 = getelementptr inbounds %struct.cJSON, ptr %79, i32 0, i32 1
  %81 = load ptr, ptr %80, align 8
  %82 = getelementptr inbounds %struct.cJSON, ptr %81, i32 0, i32 0
  store ptr %78, ptr %82, align 8
  br label %83

83:                                               ; preds = %77, %72
  %84 = load ptr, ptr %7, align 8
  %85 = getelementptr inbounds %struct.cJSON, ptr %84, i32 0, i32 0
  %86 = load ptr, ptr %85, align 8
  %87 = icmp eq ptr %86, null
  br i1 %87, label %88, label %94

88:                                               ; preds = %83
  %89 = load ptr, ptr %7, align 8
  %90 = load ptr, ptr %5, align 8
  %91 = getelementptr inbounds %struct.cJSON, ptr %90, i32 0, i32 2
  %92 = load ptr, ptr %91, align 8
  %93 = getelementptr inbounds %struct.cJSON, ptr %92, i32 0, i32 1
  store ptr %89, ptr %93, align 8
  br label %94

94:                                               ; preds = %88, %83
  br label %95

95:                                               ; preds = %94, %68
  %96 = load ptr, ptr %6, align 8
  %97 = getelementptr inbounds %struct.cJSON, ptr %96, i32 0, i32 0
  store ptr null, ptr %97, align 8
  %98 = load ptr, ptr %6, align 8
  %99 = getelementptr inbounds %struct.cJSON, ptr %98, i32 0, i32 1
  store ptr null, ptr %99, align 8
  %100 = load ptr, ptr %6, align 8
  call void @cJSON_Delete(ptr noundef %100)
  store i32 1, ptr %4, align 4
  br label %101

101:                                              ; preds = %95, %26, %21
  %102 = load i32, ptr %4, align 4
  ret i32 %102
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_ReplaceItemInArray(ptr noundef %0, i32 noundef %1, ptr noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store i32 %1, ptr %6, align 4
  store ptr %2, ptr %7, align 8
  %8 = load i32, ptr %6, align 4
  %9 = icmp slt i32 %8, 0
  br i1 %9, label %10, label %11

10:                                               ; preds = %3
  store i32 0, ptr %4, align 4
  br label %19

11:                                               ; preds = %3
  %12 = load ptr, ptr %5, align 8
  %13 = load ptr, ptr %5, align 8
  %14 = load i32, ptr %6, align 4
  %15 = sext i32 %14 to i64
  %16 = call ptr @get_array_item(ptr noundef %13, i64 noundef %15)
  %17 = load ptr, ptr %7, align 8
  %18 = call i32 @cJSON_ReplaceItemViaPointer(ptr noundef %12, ptr noundef %16, ptr noundef %17)
  store i32 %18, ptr %4, align 4
  br label %19

19:                                               ; preds = %11, %10
  %20 = load i32, ptr %4, align 4
  ret i32 %20
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_ReplaceItemInObject(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr %2, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = load ptr, ptr %6, align 8
  %10 = call i32 @replace_item_in_object(ptr noundef %7, ptr noundef %8, ptr noundef %9, i32 noundef 0)
  ret i32 %10
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @replace_item_in_object(ptr noundef %0, ptr noundef %1, ptr noundef %2, i32 noundef %3) #0 {
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca i32, align 4
  store ptr %0, ptr %6, align 8
  store ptr %1, ptr %7, align 8
  store ptr %2, ptr %8, align 8
  store i32 %3, ptr %9, align 4
  %10 = load ptr, ptr %8, align 8
  %11 = icmp eq ptr %10, null
  br i1 %11, label %15, label %12

12:                                               ; preds = %4
  %13 = load ptr, ptr %7, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %12, %4
  store i32 0, ptr %5, align 4
  br label %53

16:                                               ; preds = %12
  %17 = load ptr, ptr %8, align 8
  %18 = getelementptr inbounds %struct.cJSON, ptr %17, i32 0, i32 3
  %19 = load i32, ptr %18, align 8
  %20 = and i32 %19, 512
  %21 = icmp ne i32 %20, 0
  br i1 %21, label %31, label %22

22:                                               ; preds = %16
  %23 = load ptr, ptr %8, align 8
  %24 = getelementptr inbounds %struct.cJSON, ptr %23, i32 0, i32 7
  %25 = load ptr, ptr %24, align 8
  %26 = icmp ne ptr %25, null
  br i1 %26, label %27, label %31

27:                                               ; preds = %22
  %28 = load ptr, ptr %8, align 8
  %29 = getelementptr inbounds %struct.cJSON, ptr %28, i32 0, i32 7
  %30 = load ptr, ptr %29, align 8
  call void @cJSON_free(ptr noundef %30)
  br label %31

31:                                               ; preds = %27, %22, %16
  %32 = load ptr, ptr %7, align 8
  %33 = call ptr @cJSON_strdup(ptr noundef %32, ptr noundef @global_hooks)
  %34 = load ptr, ptr %8, align 8
  %35 = getelementptr inbounds %struct.cJSON, ptr %34, i32 0, i32 7
  store ptr %33, ptr %35, align 8
  %36 = load ptr, ptr %8, align 8
  %37 = getelementptr inbounds %struct.cJSON, ptr %36, i32 0, i32 7
  %38 = load ptr, ptr %37, align 8
  %39 = icmp eq ptr %38, null
  br i1 %39, label %40, label %41

40:                                               ; preds = %31
  store i32 0, ptr %5, align 4
  br label %53

41:                                               ; preds = %31
  %42 = load ptr, ptr %8, align 8
  %43 = getelementptr inbounds %struct.cJSON, ptr %42, i32 0, i32 3
  %44 = load i32, ptr %43, align 8
  %45 = and i32 %44, -513
  store i32 %45, ptr %43, align 8
  %46 = load ptr, ptr %6, align 8
  %47 = load ptr, ptr %6, align 8
  %48 = load ptr, ptr %7, align 8
  %49 = load i32, ptr %9, align 4
  %50 = call ptr @get_object_item(ptr noundef %47, ptr noundef %48, i32 noundef %49)
  %51 = load ptr, ptr %8, align 8
  %52 = call i32 @cJSON_ReplaceItemViaPointer(ptr noundef %46, ptr noundef %50, ptr noundef %51)
  store i32 %52, ptr %5, align 4
  br label %53

53:                                               ; preds = %41, %40, %15
  %54 = load i32, ptr %5, align 4
  ret i32 %54
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_ReplaceItemInObjectCaseSensitive(ptr noundef %0, ptr noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr %2, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = load ptr, ptr %5, align 8
  %9 = load ptr, ptr %6, align 8
  %10 = call i32 @replace_item_in_object(ptr noundef %7, ptr noundef %8, ptr noundef %9, i32 noundef 1)
  ret i32 %10
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateStringReference(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  store i32 272, ptr %9, align 8
  %10 = load ptr, ptr %2, align 8
  %11 = call ptr @cast_away_const(ptr noundef %10)
  %12 = load ptr, ptr %3, align 8
  %13 = getelementptr inbounds %struct.cJSON, ptr %12, i32 0, i32 4
  store ptr %11, ptr %13, align 8
  br label %14

14:                                               ; preds = %7, %1
  %15 = load ptr, ptr %3, align 8
  ret ptr %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateObjectReference(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  store i32 320, ptr %9, align 8
  %10 = load ptr, ptr %2, align 8
  %11 = call ptr @cast_away_const(ptr noundef %10)
  %12 = load ptr, ptr %3, align 8
  %13 = getelementptr inbounds %struct.cJSON, ptr %12, i32 0, i32 2
  store ptr %11, ptr %13, align 8
  br label %14

14:                                               ; preds = %7, %1
  %15 = load ptr, ptr %3, align 8
  ret ptr %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateArrayReference(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = icmp ne ptr %5, null
  br i1 %6, label %7, label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  store i32 288, ptr %9, align 8
  %10 = load ptr, ptr %2, align 8
  %11 = call ptr @cast_away_const(ptr noundef %10)
  %12 = load ptr, ptr %3, align 8
  %13 = getelementptr inbounds %struct.cJSON, ptr %12, i32 0, i32 2
  store ptr %11, ptr %13, align 8
  br label %14

14:                                               ; preds = %7, %1
  %15 = load ptr, ptr %3, align 8
  ret ptr %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateIntArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  %10 = load i32, ptr %5, align 4
  %11 = icmp slt i32 %10, 0
  br i1 %11, label %15, label %12

12:                                               ; preds = %2
  %13 = load ptr, ptr %4, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %12, %2
  store ptr null, ptr %3, align 8
  br label %70

16:                                               ; preds = %12
  %17 = call ptr @cJSON_CreateArray()
  store ptr %17, ptr %9, align 8
  store i64 0, ptr %6, align 8
  br label %18

18:                                               ; preds = %51, %16
  %19 = load ptr, ptr %9, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %26

21:                                               ; preds = %18
  %22 = load i64, ptr %6, align 8
  %23 = load i32, ptr %5, align 4
  %24 = sext i32 %23 to i64
  %25 = icmp ult i64 %22, %24
  br label %26

26:                                               ; preds = %21, %18
  %27 = phi i1 [ false, %18 ], [ %25, %21 ]
  br i1 %27, label %28, label %54

28:                                               ; preds = %26
  %29 = load ptr, ptr %4, align 8
  %30 = load i64, ptr %6, align 8
  %31 = getelementptr inbounds i32, ptr %29, i64 %30
  %32 = load i32, ptr %31, align 4
  %33 = sitofp i32 %32 to double
  %34 = call ptr @cJSON_CreateNumber(double noundef %33)
  store ptr %34, ptr %7, align 8
  %35 = load ptr, ptr %7, align 8
  %36 = icmp ne ptr %35, null
  br i1 %36, label %39, label %37

37:                                               ; preds = %28
  %38 = load ptr, ptr %9, align 8
  call void @cJSON_Delete(ptr noundef %38)
  store ptr null, ptr %3, align 8
  br label %70

39:                                               ; preds = %28
  %40 = load i64, ptr %6, align 8
  %41 = icmp ne i64 %40, 0
  br i1 %41, label %46, label %42

42:                                               ; preds = %39
  %43 = load ptr, ptr %7, align 8
  %44 = load ptr, ptr %9, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 2
  store ptr %43, ptr %45, align 8
  br label %49

46:                                               ; preds = %39
  %47 = load ptr, ptr %8, align 8
  %48 = load ptr, ptr %7, align 8
  call void @suffix_object(ptr noundef %47, ptr noundef %48)
  br label %49

49:                                               ; preds = %46, %42
  %50 = load ptr, ptr %7, align 8
  store ptr %50, ptr %8, align 8
  br label %51

51:                                               ; preds = %49
  %52 = load i64, ptr %6, align 8
  %53 = add i64 %52, 1
  store i64 %53, ptr %6, align 8
  br label %18, !llvm.loop !29

54:                                               ; preds = %26
  %55 = load ptr, ptr %9, align 8
  %56 = icmp ne ptr %55, null
  br i1 %56, label %57, label %68

57:                                               ; preds = %54
  %58 = load ptr, ptr %9, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 2
  %60 = load ptr, ptr %59, align 8
  %61 = icmp ne ptr %60, null
  br i1 %61, label %62, label %68

62:                                               ; preds = %57
  %63 = load ptr, ptr %7, align 8
  %64 = load ptr, ptr %9, align 8
  %65 = getelementptr inbounds %struct.cJSON, ptr %64, i32 0, i32 2
  %66 = load ptr, ptr %65, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 1
  store ptr %63, ptr %67, align 8
  br label %68

68:                                               ; preds = %62, %57, %54
  %69 = load ptr, ptr %9, align 8
  store ptr %69, ptr %3, align 8
  br label %70

70:                                               ; preds = %68, %37, %15
  %71 = load ptr, ptr %3, align 8
  ret ptr %71
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateFloatArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  %10 = load i32, ptr %5, align 4
  %11 = icmp slt i32 %10, 0
  br i1 %11, label %15, label %12

12:                                               ; preds = %2
  %13 = load ptr, ptr %4, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %12, %2
  store ptr null, ptr %3, align 8
  br label %70

16:                                               ; preds = %12
  %17 = call ptr @cJSON_CreateArray()
  store ptr %17, ptr %9, align 8
  store i64 0, ptr %6, align 8
  br label %18

18:                                               ; preds = %51, %16
  %19 = load ptr, ptr %9, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %26

21:                                               ; preds = %18
  %22 = load i64, ptr %6, align 8
  %23 = load i32, ptr %5, align 4
  %24 = sext i32 %23 to i64
  %25 = icmp ult i64 %22, %24
  br label %26

26:                                               ; preds = %21, %18
  %27 = phi i1 [ false, %18 ], [ %25, %21 ]
  br i1 %27, label %28, label %54

28:                                               ; preds = %26
  %29 = load ptr, ptr %4, align 8
  %30 = load i64, ptr %6, align 8
  %31 = getelementptr inbounds float, ptr %29, i64 %30
  %32 = load float, ptr %31, align 4
  %33 = fpext float %32 to double
  %34 = call ptr @cJSON_CreateNumber(double noundef %33)
  store ptr %34, ptr %7, align 8
  %35 = load ptr, ptr %7, align 8
  %36 = icmp ne ptr %35, null
  br i1 %36, label %39, label %37

37:                                               ; preds = %28
  %38 = load ptr, ptr %9, align 8
  call void @cJSON_Delete(ptr noundef %38)
  store ptr null, ptr %3, align 8
  br label %70

39:                                               ; preds = %28
  %40 = load i64, ptr %6, align 8
  %41 = icmp ne i64 %40, 0
  br i1 %41, label %46, label %42

42:                                               ; preds = %39
  %43 = load ptr, ptr %7, align 8
  %44 = load ptr, ptr %9, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 2
  store ptr %43, ptr %45, align 8
  br label %49

46:                                               ; preds = %39
  %47 = load ptr, ptr %8, align 8
  %48 = load ptr, ptr %7, align 8
  call void @suffix_object(ptr noundef %47, ptr noundef %48)
  br label %49

49:                                               ; preds = %46, %42
  %50 = load ptr, ptr %7, align 8
  store ptr %50, ptr %8, align 8
  br label %51

51:                                               ; preds = %49
  %52 = load i64, ptr %6, align 8
  %53 = add i64 %52, 1
  store i64 %53, ptr %6, align 8
  br label %18, !llvm.loop !30

54:                                               ; preds = %26
  %55 = load ptr, ptr %9, align 8
  %56 = icmp ne ptr %55, null
  br i1 %56, label %57, label %68

57:                                               ; preds = %54
  %58 = load ptr, ptr %9, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 2
  %60 = load ptr, ptr %59, align 8
  %61 = icmp ne ptr %60, null
  br i1 %61, label %62, label %68

62:                                               ; preds = %57
  %63 = load ptr, ptr %7, align 8
  %64 = load ptr, ptr %9, align 8
  %65 = getelementptr inbounds %struct.cJSON, ptr %64, i32 0, i32 2
  %66 = load ptr, ptr %65, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 1
  store ptr %63, ptr %67, align 8
  br label %68

68:                                               ; preds = %62, %57, %54
  %69 = load ptr, ptr %9, align 8
  store ptr %69, ptr %3, align 8
  br label %70

70:                                               ; preds = %68, %37, %15
  %71 = load ptr, ptr %3, align 8
  ret ptr %71
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateDoubleArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  %10 = load i32, ptr %5, align 4
  %11 = icmp slt i32 %10, 0
  br i1 %11, label %15, label %12

12:                                               ; preds = %2
  %13 = load ptr, ptr %4, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %12, %2
  store ptr null, ptr %3, align 8
  br label %69

16:                                               ; preds = %12
  %17 = call ptr @cJSON_CreateArray()
  store ptr %17, ptr %9, align 8
  store i64 0, ptr %6, align 8
  br label %18

18:                                               ; preds = %50, %16
  %19 = load ptr, ptr %9, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %26

21:                                               ; preds = %18
  %22 = load i64, ptr %6, align 8
  %23 = load i32, ptr %5, align 4
  %24 = sext i32 %23 to i64
  %25 = icmp ult i64 %22, %24
  br label %26

26:                                               ; preds = %21, %18
  %27 = phi i1 [ false, %18 ], [ %25, %21 ]
  br i1 %27, label %28, label %53

28:                                               ; preds = %26
  %29 = load ptr, ptr %4, align 8
  %30 = load i64, ptr %6, align 8
  %31 = getelementptr inbounds double, ptr %29, i64 %30
  %32 = load double, ptr %31, align 8
  %33 = call ptr @cJSON_CreateNumber(double noundef %32)
  store ptr %33, ptr %7, align 8
  %34 = load ptr, ptr %7, align 8
  %35 = icmp ne ptr %34, null
  br i1 %35, label %38, label %36

36:                                               ; preds = %28
  %37 = load ptr, ptr %9, align 8
  call void @cJSON_Delete(ptr noundef %37)
  store ptr null, ptr %3, align 8
  br label %69

38:                                               ; preds = %28
  %39 = load i64, ptr %6, align 8
  %40 = icmp ne i64 %39, 0
  br i1 %40, label %45, label %41

41:                                               ; preds = %38
  %42 = load ptr, ptr %7, align 8
  %43 = load ptr, ptr %9, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 2
  store ptr %42, ptr %44, align 8
  br label %48

45:                                               ; preds = %38
  %46 = load ptr, ptr %8, align 8
  %47 = load ptr, ptr %7, align 8
  call void @suffix_object(ptr noundef %46, ptr noundef %47)
  br label %48

48:                                               ; preds = %45, %41
  %49 = load ptr, ptr %7, align 8
  store ptr %49, ptr %8, align 8
  br label %50

50:                                               ; preds = %48
  %51 = load i64, ptr %6, align 8
  %52 = add i64 %51, 1
  store i64 %52, ptr %6, align 8
  br label %18, !llvm.loop !31

53:                                               ; preds = %26
  %54 = load ptr, ptr %9, align 8
  %55 = icmp ne ptr %54, null
  br i1 %55, label %56, label %67

56:                                               ; preds = %53
  %57 = load ptr, ptr %9, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 2
  %59 = load ptr, ptr %58, align 8
  %60 = icmp ne ptr %59, null
  br i1 %60, label %61, label %67

61:                                               ; preds = %56
  %62 = load ptr, ptr %7, align 8
  %63 = load ptr, ptr %9, align 8
  %64 = getelementptr inbounds %struct.cJSON, ptr %63, i32 0, i32 2
  %65 = load ptr, ptr %64, align 8
  %66 = getelementptr inbounds %struct.cJSON, ptr %65, i32 0, i32 1
  store ptr %62, ptr %66, align 8
  br label %67

67:                                               ; preds = %61, %56, %53
  %68 = load ptr, ptr %9, align 8
  store ptr %68, ptr %3, align 8
  br label %69

69:                                               ; preds = %67, %36, %15
  %70 = load ptr, ptr %3, align 8
  ret ptr %70
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_CreateStringArray(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  %10 = load i32, ptr %5, align 4
  %11 = icmp slt i32 %10, 0
  br i1 %11, label %15, label %12

12:                                               ; preds = %2
  %13 = load ptr, ptr %4, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %15, label %16

15:                                               ; preds = %12, %2
  store ptr null, ptr %3, align 8
  br label %69

16:                                               ; preds = %12
  %17 = call ptr @cJSON_CreateArray()
  store ptr %17, ptr %9, align 8
  store i64 0, ptr %6, align 8
  br label %18

18:                                               ; preds = %50, %16
  %19 = load ptr, ptr %9, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %26

21:                                               ; preds = %18
  %22 = load i64, ptr %6, align 8
  %23 = load i32, ptr %5, align 4
  %24 = sext i32 %23 to i64
  %25 = icmp ult i64 %22, %24
  br label %26

26:                                               ; preds = %21, %18
  %27 = phi i1 [ false, %18 ], [ %25, %21 ]
  br i1 %27, label %28, label %53

28:                                               ; preds = %26
  %29 = load ptr, ptr %4, align 8
  %30 = load i64, ptr %6, align 8
  %31 = getelementptr inbounds ptr, ptr %29, i64 %30
  %32 = load ptr, ptr %31, align 8
  %33 = call ptr @cJSON_CreateString(ptr noundef %32)
  store ptr %33, ptr %7, align 8
  %34 = load ptr, ptr %7, align 8
  %35 = icmp ne ptr %34, null
  br i1 %35, label %38, label %36

36:                                               ; preds = %28
  %37 = load ptr, ptr %9, align 8
  call void @cJSON_Delete(ptr noundef %37)
  store ptr null, ptr %3, align 8
  br label %69

38:                                               ; preds = %28
  %39 = load i64, ptr %6, align 8
  %40 = icmp ne i64 %39, 0
  br i1 %40, label %45, label %41

41:                                               ; preds = %38
  %42 = load ptr, ptr %7, align 8
  %43 = load ptr, ptr %9, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 2
  store ptr %42, ptr %44, align 8
  br label %48

45:                                               ; preds = %38
  %46 = load ptr, ptr %8, align 8
  %47 = load ptr, ptr %7, align 8
  call void @suffix_object(ptr noundef %46, ptr noundef %47)
  br label %48

48:                                               ; preds = %45, %41
  %49 = load ptr, ptr %7, align 8
  store ptr %49, ptr %8, align 8
  br label %50

50:                                               ; preds = %48
  %51 = load i64, ptr %6, align 8
  %52 = add i64 %51, 1
  store i64 %52, ptr %6, align 8
  br label %18, !llvm.loop !32

53:                                               ; preds = %26
  %54 = load ptr, ptr %9, align 8
  %55 = icmp ne ptr %54, null
  br i1 %55, label %56, label %67

56:                                               ; preds = %53
  %57 = load ptr, ptr %9, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 2
  %59 = load ptr, ptr %58, align 8
  %60 = icmp ne ptr %59, null
  br i1 %60, label %61, label %67

61:                                               ; preds = %56
  %62 = load ptr, ptr %7, align 8
  %63 = load ptr, ptr %9, align 8
  %64 = getelementptr inbounds %struct.cJSON, ptr %63, i32 0, i32 2
  %65 = load ptr, ptr %64, align 8
  %66 = getelementptr inbounds %struct.cJSON, ptr %65, i32 0, i32 1
  store ptr %62, ptr %66, align 8
  br label %67

67:                                               ; preds = %61, %56, %53
  %68 = load ptr, ptr %9, align 8
  store ptr %68, ptr %3, align 8
  br label %69

69:                                               ; preds = %67, %36, %15
  %70 = load ptr, ptr %3, align 8
  ret ptr %70
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_Duplicate(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store i32 %1, ptr %4, align 4
  %5 = load ptr, ptr %3, align 8
  %6 = load i32, ptr %4, align 4
  %7 = call ptr @cJSON_Duplicate_rec(ptr noundef %5, i64 noundef 0, i32 noundef %6)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_Duplicate_rec(ptr noundef %0, i64 noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store i64 %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  store ptr null, ptr %10, align 8
  store ptr null, ptr %11, align 8
  %12 = load ptr, ptr %5, align 8
  %13 = icmp ne ptr %12, null
  br i1 %13, label %15, label %14

14:                                               ; preds = %3
  br label %144

15:                                               ; preds = %3
  %16 = call ptr @cJSON_New_Item(ptr noundef @global_hooks)
  store ptr %16, ptr %8, align 8
  %17 = load ptr, ptr %8, align 8
  %18 = icmp ne ptr %17, null
  br i1 %18, label %20, label %19

19:                                               ; preds = %15
  br label %144

20:                                               ; preds = %15
  %21 = load ptr, ptr %5, align 8
  %22 = getelementptr inbounds %struct.cJSON, ptr %21, i32 0, i32 3
  %23 = load i32, ptr %22, align 8
  %24 = and i32 %23, -257
  %25 = load ptr, ptr %8, align 8
  %26 = getelementptr inbounds %struct.cJSON, ptr %25, i32 0, i32 3
  store i32 %24, ptr %26, align 8
  %27 = load ptr, ptr %5, align 8
  %28 = getelementptr inbounds %struct.cJSON, ptr %27, i32 0, i32 5
  %29 = load i32, ptr %28, align 8
  %30 = load ptr, ptr %8, align 8
  %31 = getelementptr inbounds %struct.cJSON, ptr %30, i32 0, i32 5
  store i32 %29, ptr %31, align 8
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 6
  %34 = load double, ptr %33, align 8
  %35 = load ptr, ptr %8, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 6
  store double %34, ptr %36, align 8
  %37 = load ptr, ptr %5, align 8
  %38 = getelementptr inbounds %struct.cJSON, ptr %37, i32 0, i32 4
  %39 = load ptr, ptr %38, align 8
  %40 = icmp ne ptr %39, null
  br i1 %40, label %41, label %54

41:                                               ; preds = %20
  %42 = load ptr, ptr %5, align 8
  %43 = getelementptr inbounds %struct.cJSON, ptr %42, i32 0, i32 4
  %44 = load ptr, ptr %43, align 8
  %45 = call ptr @cJSON_strdup(ptr noundef %44, ptr noundef @global_hooks)
  %46 = load ptr, ptr %8, align 8
  %47 = getelementptr inbounds %struct.cJSON, ptr %46, i32 0, i32 4
  store ptr %45, ptr %47, align 8
  %48 = load ptr, ptr %8, align 8
  %49 = getelementptr inbounds %struct.cJSON, ptr %48, i32 0, i32 4
  %50 = load ptr, ptr %49, align 8
  %51 = icmp ne ptr %50, null
  br i1 %51, label %53, label %52

52:                                               ; preds = %41
  br label %144

53:                                               ; preds = %41
  br label %54

54:                                               ; preds = %53, %20
  %55 = load ptr, ptr %5, align 8
  %56 = getelementptr inbounds %struct.cJSON, ptr %55, i32 0, i32 7
  %57 = load ptr, ptr %56, align 8
  %58 = icmp ne ptr %57, null
  br i1 %58, label %59, label %84

59:                                               ; preds = %54
  %60 = load ptr, ptr %5, align 8
  %61 = getelementptr inbounds %struct.cJSON, ptr %60, i32 0, i32 3
  %62 = load i32, ptr %61, align 8
  %63 = and i32 %62, 512
  %64 = icmp ne i32 %63, 0
  br i1 %64, label %65, label %69

65:                                               ; preds = %59
  %66 = load ptr, ptr %5, align 8
  %67 = getelementptr inbounds %struct.cJSON, ptr %66, i32 0, i32 7
  %68 = load ptr, ptr %67, align 8
  br label %74

69:                                               ; preds = %59
  %70 = load ptr, ptr %5, align 8
  %71 = getelementptr inbounds %struct.cJSON, ptr %70, i32 0, i32 7
  %72 = load ptr, ptr %71, align 8
  %73 = call ptr @cJSON_strdup(ptr noundef %72, ptr noundef @global_hooks)
  br label %74

74:                                               ; preds = %69, %65
  %75 = phi ptr [ %68, %65 ], [ %73, %69 ]
  %76 = load ptr, ptr %8, align 8
  %77 = getelementptr inbounds %struct.cJSON, ptr %76, i32 0, i32 7
  store ptr %75, ptr %77, align 8
  %78 = load ptr, ptr %8, align 8
  %79 = getelementptr inbounds %struct.cJSON, ptr %78, i32 0, i32 7
  %80 = load ptr, ptr %79, align 8
  %81 = icmp ne ptr %80, null
  br i1 %81, label %83, label %82

82:                                               ; preds = %74
  br label %144

83:                                               ; preds = %74
  br label %84

84:                                               ; preds = %83, %54
  %85 = load i32, ptr %7, align 4
  %86 = icmp ne i32 %85, 0
  br i1 %86, label %89, label %87

87:                                               ; preds = %84
  %88 = load ptr, ptr %8, align 8
  store ptr %88, ptr %4, align 8
  br label %150

89:                                               ; preds = %84
  %90 = load ptr, ptr %5, align 8
  %91 = getelementptr inbounds %struct.cJSON, ptr %90, i32 0, i32 2
  %92 = load ptr, ptr %91, align 8
  store ptr %92, ptr %9, align 8
  br label %93

93:                                               ; preds = %124, %89
  %94 = load ptr, ptr %9, align 8
  %95 = icmp ne ptr %94, null
  br i1 %95, label %96, label %128

96:                                               ; preds = %93
  %97 = load i64, ptr %6, align 8
  %98 = icmp uge i64 %97, 10000
  br i1 %98, label %99, label %100

99:                                               ; preds = %96
  br label %144

100:                                              ; preds = %96
  %101 = load ptr, ptr %9, align 8
  %102 = load i64, ptr %6, align 8
  %103 = add i64 %102, 1
  %104 = call ptr @cJSON_Duplicate_rec(ptr noundef %101, i64 noundef %103, i32 noundef 1)
  store ptr %104, ptr %11, align 8
  %105 = load ptr, ptr %11, align 8
  %106 = icmp ne ptr %105, null
  br i1 %106, label %108, label %107

107:                                              ; preds = %100
  br label %144

108:                                              ; preds = %100
  %109 = load ptr, ptr %10, align 8
  %110 = icmp ne ptr %109, null
  br i1 %110, label %111, label %119

111:                                              ; preds = %108
  %112 = load ptr, ptr %11, align 8
  %113 = load ptr, ptr %10, align 8
  %114 = getelementptr inbounds %struct.cJSON, ptr %113, i32 0, i32 0
  store ptr %112, ptr %114, align 8
  %115 = load ptr, ptr %10, align 8
  %116 = load ptr, ptr %11, align 8
  %117 = getelementptr inbounds %struct.cJSON, ptr %116, i32 0, i32 1
  store ptr %115, ptr %117, align 8
  %118 = load ptr, ptr %11, align 8
  store ptr %118, ptr %10, align 8
  br label %124

119:                                              ; preds = %108
  %120 = load ptr, ptr %11, align 8
  %121 = load ptr, ptr %8, align 8
  %122 = getelementptr inbounds %struct.cJSON, ptr %121, i32 0, i32 2
  store ptr %120, ptr %122, align 8
  %123 = load ptr, ptr %11, align 8
  store ptr %123, ptr %10, align 8
  br label %124

124:                                              ; preds = %119, %111
  %125 = load ptr, ptr %9, align 8
  %126 = getelementptr inbounds %struct.cJSON, ptr %125, i32 0, i32 0
  %127 = load ptr, ptr %126, align 8
  store ptr %127, ptr %9, align 8
  br label %93, !llvm.loop !33

128:                                              ; preds = %93
  %129 = load ptr, ptr %8, align 8
  %130 = icmp ne ptr %129, null
  br i1 %130, label %131, label %142

131:                                              ; preds = %128
  %132 = load ptr, ptr %8, align 8
  %133 = getelementptr inbounds %struct.cJSON, ptr %132, i32 0, i32 2
  %134 = load ptr, ptr %133, align 8
  %135 = icmp ne ptr %134, null
  br i1 %135, label %136, label %142

136:                                              ; preds = %131
  %137 = load ptr, ptr %11, align 8
  %138 = load ptr, ptr %8, align 8
  %139 = getelementptr inbounds %struct.cJSON, ptr %138, i32 0, i32 2
  %140 = load ptr, ptr %139, align 8
  %141 = getelementptr inbounds %struct.cJSON, ptr %140, i32 0, i32 1
  store ptr %137, ptr %141, align 8
  br label %142

142:                                              ; preds = %136, %131, %128
  %143 = load ptr, ptr %8, align 8
  store ptr %143, ptr %4, align 8
  br label %150

144:                                              ; preds = %107, %99, %82, %52, %19, %14
  %145 = load ptr, ptr %8, align 8
  %146 = icmp ne ptr %145, null
  br i1 %146, label %147, label %149

147:                                              ; preds = %144
  %148 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %148)
  br label %149

149:                                              ; preds = %147, %144
  store ptr null, ptr %4, align 8
  br label %150

150:                                              ; preds = %149, %142, %87
  %151 = load ptr, ptr %4, align 8
  ret ptr %151
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSON_Minify(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %2, align 8
  %6 = icmp eq ptr %5, null
  br i1 %6, label %7, label %8

7:                                                ; preds = %1
  br label %56

8:                                                ; preds = %1
  br label %9

9:                                                ; preds = %53, %8
  %10 = load ptr, ptr %2, align 8
  %11 = getelementptr inbounds i8, ptr %10, i64 0
  %12 = load i8, ptr %11, align 1
  %13 = zext i8 %12 to i32
  %14 = icmp ne i32 %13, 0
  br i1 %14, label %15, label %54

15:                                               ; preds = %9
  %16 = load ptr, ptr %2, align 8
  %17 = getelementptr inbounds i8, ptr %16, i64 0
  %18 = load i8, ptr %17, align 1
  %19 = zext i8 %18 to i32
  switch i32 %19, label %43 [
    i32 32, label %20
    i32 9, label %20
    i32 13, label %20
    i32 10, label %20
    i32 47, label %23
    i32 34, label %42
  ]

20:                                               ; preds = %15, %15, %15, %15
  %21 = load ptr, ptr %2, align 8
  %22 = getelementptr inbounds i8, ptr %21, i32 1
  store ptr %22, ptr %2, align 8
  br label %53

23:                                               ; preds = %15
  %24 = load ptr, ptr %2, align 8
  %25 = getelementptr inbounds i8, ptr %24, i64 1
  %26 = load i8, ptr %25, align 1
  %27 = zext i8 %26 to i32
  %28 = icmp eq i32 %27, 47
  br i1 %28, label %29, label %30

29:                                               ; preds = %23
  call void @skip_oneline_comment(ptr noundef %2)
  br label %41

30:                                               ; preds = %23
  %31 = load ptr, ptr %2, align 8
  %32 = getelementptr inbounds i8, ptr %31, i64 1
  %33 = load i8, ptr %32, align 1
  %34 = zext i8 %33 to i32
  %35 = icmp eq i32 %34, 42
  br i1 %35, label %36, label %37

36:                                               ; preds = %30
  call void @skip_multiline_comment(ptr noundef %2)
  br label %40

37:                                               ; preds = %30
  %38 = load ptr, ptr %2, align 8
  %39 = getelementptr inbounds i8, ptr %38, i32 1
  store ptr %39, ptr %2, align 8
  br label %40

40:                                               ; preds = %37, %36
  br label %41

41:                                               ; preds = %40, %29
  br label %53

42:                                               ; preds = %15
  call void @minify_string(ptr noundef %2, ptr noundef %3)
  br label %53

43:                                               ; preds = %15
  %44 = load ptr, ptr %2, align 8
  %45 = getelementptr inbounds i8, ptr %44, i64 0
  %46 = load i8, ptr %45, align 1
  %47 = load ptr, ptr %3, align 8
  %48 = getelementptr inbounds i8, ptr %47, i64 0
  store i8 %46, ptr %48, align 1
  %49 = load ptr, ptr %2, align 8
  %50 = getelementptr inbounds i8, ptr %49, i32 1
  store ptr %50, ptr %2, align 8
  %51 = load ptr, ptr %3, align 8
  %52 = getelementptr inbounds i8, ptr %51, i32 1
  store ptr %52, ptr %3, align 8
  br label %53

53:                                               ; preds = %43, %42, %41, %20
  br label %9, !llvm.loop !34

54:                                               ; preds = %9
  %55 = load ptr, ptr %3, align 8
  store i8 0, ptr %55, align 1
  br label %56

56:                                               ; preds = %54, %7
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @skip_oneline_comment(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = getelementptr inbounds i8, ptr %4, i64 2
  store ptr %5, ptr %3, align 8
  br label %6

6:                                                ; preds = %25, %1
  %7 = load ptr, ptr %2, align 8
  %8 = load ptr, ptr %7, align 8
  %9 = getelementptr inbounds i8, ptr %8, i64 0
  %10 = load i8, ptr %9, align 1
  %11 = zext i8 %10 to i32
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %29

13:                                               ; preds = %6
  %14 = load ptr, ptr %2, align 8
  %15 = load ptr, ptr %14, align 8
  %16 = getelementptr inbounds i8, ptr %15, i64 0
  %17 = load i8, ptr %16, align 1
  %18 = zext i8 %17 to i32
  %19 = icmp eq i32 %18, 10
  br i1 %19, label %20, label %24

20:                                               ; preds = %13
  %21 = load ptr, ptr %2, align 8
  %22 = load ptr, ptr %21, align 8
  %23 = getelementptr inbounds i8, ptr %22, i64 1
  store ptr %23, ptr %21, align 8
  br label %29

24:                                               ; preds = %13
  br label %25

25:                                               ; preds = %24
  %26 = load ptr, ptr %2, align 8
  %27 = load ptr, ptr %26, align 8
  %28 = getelementptr inbounds i8, ptr %27, i32 1
  store ptr %28, ptr %26, align 8
  br label %6, !llvm.loop !35

29:                                               ; preds = %20, %6
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @skip_multiline_comment(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = getelementptr inbounds i8, ptr %4, i64 2
  store ptr %5, ptr %3, align 8
  br label %6

6:                                                ; preds = %32, %1
  %7 = load ptr, ptr %2, align 8
  %8 = load ptr, ptr %7, align 8
  %9 = getelementptr inbounds i8, ptr %8, i64 0
  %10 = load i8, ptr %9, align 1
  %11 = zext i8 %10 to i32
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %13, label %36

13:                                               ; preds = %6
  %14 = load ptr, ptr %2, align 8
  %15 = load ptr, ptr %14, align 8
  %16 = getelementptr inbounds i8, ptr %15, i64 0
  %17 = load i8, ptr %16, align 1
  %18 = zext i8 %17 to i32
  %19 = icmp eq i32 %18, 42
  br i1 %19, label %20, label %31

20:                                               ; preds = %13
  %21 = load ptr, ptr %2, align 8
  %22 = load ptr, ptr %21, align 8
  %23 = getelementptr inbounds i8, ptr %22, i64 1
  %24 = load i8, ptr %23, align 1
  %25 = zext i8 %24 to i32
  %26 = icmp eq i32 %25, 47
  br i1 %26, label %27, label %31

27:                                               ; preds = %20
  %28 = load ptr, ptr %2, align 8
  %29 = load ptr, ptr %28, align 8
  %30 = getelementptr inbounds i8, ptr %29, i64 2
  store ptr %30, ptr %28, align 8
  br label %36

31:                                               ; preds = %20, %13
  br label %32

32:                                               ; preds = %31
  %33 = load ptr, ptr %2, align 8
  %34 = load ptr, ptr %33, align 8
  %35 = getelementptr inbounds i8, ptr %34, i32 1
  store ptr %35, ptr %33, align 8
  br label %6, !llvm.loop !36

36:                                               ; preds = %27, %6
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @minify_string(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %5, align 8
  %7 = getelementptr inbounds i8, ptr %6, i64 0
  %8 = load i8, ptr %7, align 1
  %9 = load ptr, ptr %4, align 8
  %10 = load ptr, ptr %9, align 8
  %11 = getelementptr inbounds i8, ptr %10, i64 0
  store i8 %8, ptr %11, align 1
  %12 = load ptr, ptr %3, align 8
  %13 = load ptr, ptr %12, align 8
  %14 = getelementptr inbounds i8, ptr %13, i64 1
  store ptr %14, ptr %12, align 8
  %15 = load ptr, ptr %4, align 8
  %16 = load ptr, ptr %15, align 8
  %17 = getelementptr inbounds i8, ptr %16, i64 1
  store ptr %17, ptr %15, align 8
  br label %18

18:                                               ; preds = %79, %2
  %19 = load ptr, ptr %3, align 8
  %20 = load ptr, ptr %19, align 8
  %21 = getelementptr inbounds i8, ptr %20, i64 0
  %22 = load i8, ptr %21, align 1
  %23 = zext i8 %22 to i32
  %24 = icmp ne i32 %23, 0
  br i1 %24, label %25, label %86

25:                                               ; preds = %18
  %26 = load ptr, ptr %3, align 8
  %27 = load ptr, ptr %26, align 8
  %28 = getelementptr inbounds i8, ptr %27, i64 0
  %29 = load i8, ptr %28, align 1
  %30 = load ptr, ptr %4, align 8
  %31 = load ptr, ptr %30, align 8
  %32 = getelementptr inbounds i8, ptr %31, i64 0
  store i8 %29, ptr %32, align 1
  %33 = load ptr, ptr %3, align 8
  %34 = load ptr, ptr %33, align 8
  %35 = getelementptr inbounds i8, ptr %34, i64 0
  %36 = load i8, ptr %35, align 1
  %37 = zext i8 %36 to i32
  %38 = icmp eq i32 %37, 34
  br i1 %38, label %39, label %49

39:                                               ; preds = %25
  %40 = load ptr, ptr %4, align 8
  %41 = load ptr, ptr %40, align 8
  %42 = getelementptr inbounds i8, ptr %41, i64 0
  store i8 34, ptr %42, align 1
  %43 = load ptr, ptr %3, align 8
  %44 = load ptr, ptr %43, align 8
  %45 = getelementptr inbounds i8, ptr %44, i64 1
  store ptr %45, ptr %43, align 8
  %46 = load ptr, ptr %4, align 8
  %47 = load ptr, ptr %46, align 8
  %48 = getelementptr inbounds i8, ptr %47, i64 1
  store ptr %48, ptr %46, align 8
  br label %86

49:                                               ; preds = %25
  %50 = load ptr, ptr %3, align 8
  %51 = load ptr, ptr %50, align 8
  %52 = getelementptr inbounds i8, ptr %51, i64 0
  %53 = load i8, ptr %52, align 1
  %54 = zext i8 %53 to i32
  %55 = icmp eq i32 %54, 92
  br i1 %55, label %56, label %77

56:                                               ; preds = %49
  %57 = load ptr, ptr %3, align 8
  %58 = load ptr, ptr %57, align 8
  %59 = getelementptr inbounds i8, ptr %58, i64 1
  %60 = load i8, ptr %59, align 1
  %61 = zext i8 %60 to i32
  %62 = icmp eq i32 %61, 34
  br i1 %62, label %63, label %77

63:                                               ; preds = %56
  %64 = load ptr, ptr %3, align 8
  %65 = load ptr, ptr %64, align 8
  %66 = getelementptr inbounds i8, ptr %65, i64 1
  %67 = load i8, ptr %66, align 1
  %68 = load ptr, ptr %4, align 8
  %69 = load ptr, ptr %68, align 8
  %70 = getelementptr inbounds i8, ptr %69, i64 1
  store i8 %67, ptr %70, align 1
  %71 = load ptr, ptr %3, align 8
  %72 = load ptr, ptr %71, align 8
  %73 = getelementptr inbounds i8, ptr %72, i64 1
  store ptr %73, ptr %71, align 8
  %74 = load ptr, ptr %4, align 8
  %75 = load ptr, ptr %74, align 8
  %76 = getelementptr inbounds i8, ptr %75, i64 1
  store ptr %76, ptr %74, align 8
  br label %77

77:                                               ; preds = %63, %56, %49
  br label %78

78:                                               ; preds = %77
  br label %79

79:                                               ; preds = %78
  %80 = load ptr, ptr %3, align 8
  %81 = load ptr, ptr %80, align 8
  %82 = getelementptr inbounds i8, ptr %81, i32 1
  store ptr %82, ptr %80, align 8
  %83 = load ptr, ptr %4, align 8
  %84 = load ptr, ptr %83, align 8
  %85 = getelementptr inbounds i8, ptr %84, i32 1
  store ptr %85, ptr %83, align 8
  br label %18, !llvm.loop !37

86:                                               ; preds = %39, %18
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsInvalid(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 0
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsFalse(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 1
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsTrue(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 2
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsBool(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 3
  %12 = icmp ne i32 %11, 0
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsNull(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 4
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsArray(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 32
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsObject(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 64
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_IsRaw(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4
  br label %14

7:                                                ; preds = %1
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 3
  %10 = load i32, ptr %9, align 8
  %11 = and i32 %10, 255
  %12 = icmp eq i32 %11, 128
  %13 = zext i1 %12 to i32
  store i32 %13, ptr %2, align 4
  br label %14

14:                                               ; preds = %7, %6
  %15 = load i32, ptr %2, align 4
  ret i32 %15
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSON_Compare(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %12 = load ptr, ptr %5, align 8
  %13 = icmp eq ptr %12, null
  br i1 %13, label %27, label %14

14:                                               ; preds = %3
  %15 = load ptr, ptr %6, align 8
  %16 = icmp eq ptr %15, null
  br i1 %16, label %27, label %17

17:                                               ; preds = %14
  %18 = load ptr, ptr %5, align 8
  %19 = getelementptr inbounds %struct.cJSON, ptr %18, i32 0, i32 3
  %20 = load i32, ptr %19, align 8
  %21 = and i32 %20, 255
  %22 = load ptr, ptr %6, align 8
  %23 = getelementptr inbounds %struct.cJSON, ptr %22, i32 0, i32 3
  %24 = load i32, ptr %23, align 8
  %25 = and i32 %24, 255
  %26 = icmp ne i32 %21, %25
  br i1 %26, label %27, label %28

27:                                               ; preds = %17, %14, %3
  store i32 0, ptr %4, align 4
  br label %186

28:                                               ; preds = %17
  %29 = load ptr, ptr %5, align 8
  %30 = getelementptr inbounds %struct.cJSON, ptr %29, i32 0, i32 3
  %31 = load i32, ptr %30, align 8
  %32 = and i32 %31, 255
  switch i32 %32, label %34 [
    i32 1, label %33
    i32 2, label %33
    i32 4, label %33
    i32 8, label %33
    i32 16, label %33
    i32 128, label %33
    i32 32, label %33
    i32 64, label %33
  ]

33:                                               ; preds = %28, %28, %28, %28, %28, %28, %28, %28
  br label %35

34:                                               ; preds = %28
  store i32 0, ptr %4, align 4
  br label %186

35:                                               ; preds = %33
  %36 = load ptr, ptr %5, align 8
  %37 = load ptr, ptr %6, align 8
  %38 = icmp eq ptr %36, %37
  br i1 %38, label %39, label %40

39:                                               ; preds = %35
  store i32 1, ptr %4, align 4
  br label %186

40:                                               ; preds = %35
  %41 = load ptr, ptr %5, align 8
  %42 = getelementptr inbounds %struct.cJSON, ptr %41, i32 0, i32 3
  %43 = load i32, ptr %42, align 8
  %44 = and i32 %43, 255
  switch i32 %44, label %185 [
    i32 1, label %45
    i32 2, label %45
    i32 4, label %45
    i32 8, label %46
    i32 16, label %57
    i32 128, label %57
    i32 32, label %79
    i32 64, label %114
  ]

45:                                               ; preds = %40, %40, %40
  store i32 1, ptr %4, align 4
  br label %186

46:                                               ; preds = %40
  %47 = load ptr, ptr %5, align 8
  %48 = getelementptr inbounds %struct.cJSON, ptr %47, i32 0, i32 6
  %49 = load double, ptr %48, align 8
  %50 = load ptr, ptr %6, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 6
  %52 = load double, ptr %51, align 8
  %53 = call i32 @compare_double(double noundef %49, double noundef %52)
  %54 = icmp ne i32 %53, 0
  br i1 %54, label %55, label %56

55:                                               ; preds = %46
  store i32 1, ptr %4, align 4
  br label %186

56:                                               ; preds = %46
  store i32 0, ptr %4, align 4
  br label %186

57:                                               ; preds = %40, %40
  %58 = load ptr, ptr %5, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 4
  %60 = load ptr, ptr %59, align 8
  %61 = icmp eq ptr %60, null
  br i1 %61, label %67, label %62

62:                                               ; preds = %57
  %63 = load ptr, ptr %6, align 8
  %64 = getelementptr inbounds %struct.cJSON, ptr %63, i32 0, i32 4
  %65 = load ptr, ptr %64, align 8
  %66 = icmp eq ptr %65, null
  br i1 %66, label %67, label %68

67:                                               ; preds = %62, %57
  store i32 0, ptr %4, align 4
  br label %186

68:                                               ; preds = %62
  %69 = load ptr, ptr %5, align 8
  %70 = getelementptr inbounds %struct.cJSON, ptr %69, i32 0, i32 4
  %71 = load ptr, ptr %70, align 8
  %72 = load ptr, ptr %6, align 8
  %73 = getelementptr inbounds %struct.cJSON, ptr %72, i32 0, i32 4
  %74 = load ptr, ptr %73, align 8
  %75 = call i32 @strcmp(ptr noundef %71, ptr noundef %74) #9
  %76 = icmp eq i32 %75, 0
  br i1 %76, label %77, label %78

77:                                               ; preds = %68
  store i32 1, ptr %4, align 4
  br label %186

78:                                               ; preds = %68
  store i32 0, ptr %4, align 4
  br label %186

79:                                               ; preds = %40
  %80 = load ptr, ptr %5, align 8
  %81 = getelementptr inbounds %struct.cJSON, ptr %80, i32 0, i32 2
  %82 = load ptr, ptr %81, align 8
  store ptr %82, ptr %8, align 8
  %83 = load ptr, ptr %6, align 8
  %84 = getelementptr inbounds %struct.cJSON, ptr %83, i32 0, i32 2
  %85 = load ptr, ptr %84, align 8
  store ptr %85, ptr %9, align 8
  br label %86

86:                                               ; preds = %101, %79
  %87 = load ptr, ptr %8, align 8
  %88 = icmp ne ptr %87, null
  br i1 %88, label %89, label %92

89:                                               ; preds = %86
  %90 = load ptr, ptr %9, align 8
  %91 = icmp ne ptr %90, null
  br label %92

92:                                               ; preds = %89, %86
  %93 = phi i1 [ false, %86 ], [ %91, %89 ]
  br i1 %93, label %94, label %108

94:                                               ; preds = %92
  %95 = load ptr, ptr %8, align 8
  %96 = load ptr, ptr %9, align 8
  %97 = load i32, ptr %7, align 4
  %98 = call i32 @cJSON_Compare(ptr noundef %95, ptr noundef %96, i32 noundef %97)
  %99 = icmp ne i32 %98, 0
  br i1 %99, label %101, label %100

100:                                              ; preds = %94
  store i32 0, ptr %4, align 4
  br label %186

101:                                              ; preds = %94
  %102 = load ptr, ptr %8, align 8
  %103 = getelementptr inbounds %struct.cJSON, ptr %102, i32 0, i32 0
  %104 = load ptr, ptr %103, align 8
  store ptr %104, ptr %8, align 8
  %105 = load ptr, ptr %9, align 8
  %106 = getelementptr inbounds %struct.cJSON, ptr %105, i32 0, i32 0
  %107 = load ptr, ptr %106, align 8
  store ptr %107, ptr %9, align 8
  br label %86, !llvm.loop !38

108:                                              ; preds = %92
  %109 = load ptr, ptr %8, align 8
  %110 = load ptr, ptr %9, align 8
  %111 = icmp ne ptr %109, %110
  br i1 %111, label %112, label %113

112:                                              ; preds = %108
  store i32 0, ptr %4, align 4
  br label %186

113:                                              ; preds = %108
  store i32 1, ptr %4, align 4
  br label %186

114:                                              ; preds = %40
  store ptr null, ptr %10, align 8
  store ptr null, ptr %11, align 8
  %115 = load ptr, ptr %5, align 8
  %116 = icmp ne ptr %115, null
  br i1 %116, label %117, label %121

117:                                              ; preds = %114
  %118 = load ptr, ptr %5, align 8
  %119 = getelementptr inbounds %struct.cJSON, ptr %118, i32 0, i32 2
  %120 = load ptr, ptr %119, align 8
  br label %122

121:                                              ; preds = %114
  br label %122

122:                                              ; preds = %121, %117
  %123 = phi ptr [ %120, %117 ], [ null, %121 ]
  store ptr %123, ptr %10, align 8
  br label %124

124:                                              ; preds = %145, %122
  %125 = load ptr, ptr %10, align 8
  %126 = icmp ne ptr %125, null
  br i1 %126, label %127, label %149

127:                                              ; preds = %124
  %128 = load ptr, ptr %6, align 8
  %129 = load ptr, ptr %10, align 8
  %130 = getelementptr inbounds %struct.cJSON, ptr %129, i32 0, i32 7
  %131 = load ptr, ptr %130, align 8
  %132 = load i32, ptr %7, align 4
  %133 = call ptr @get_object_item(ptr noundef %128, ptr noundef %131, i32 noundef %132)
  store ptr %133, ptr %11, align 8
  %134 = load ptr, ptr %11, align 8
  %135 = icmp eq ptr %134, null
  br i1 %135, label %136, label %137

136:                                              ; preds = %127
  store i32 0, ptr %4, align 4
  br label %186

137:                                              ; preds = %127
  %138 = load ptr, ptr %10, align 8
  %139 = load ptr, ptr %11, align 8
  %140 = load i32, ptr %7, align 4
  %141 = call i32 @cJSON_Compare(ptr noundef %138, ptr noundef %139, i32 noundef %140)
  %142 = icmp ne i32 %141, 0
  br i1 %142, label %144, label %143

143:                                              ; preds = %137
  store i32 0, ptr %4, align 4
  br label %186

144:                                              ; preds = %137
  br label %145

145:                                              ; preds = %144
  %146 = load ptr, ptr %10, align 8
  %147 = getelementptr inbounds %struct.cJSON, ptr %146, i32 0, i32 0
  %148 = load ptr, ptr %147, align 8
  store ptr %148, ptr %10, align 8
  br label %124, !llvm.loop !39

149:                                              ; preds = %124
  %150 = load ptr, ptr %6, align 8
  %151 = icmp ne ptr %150, null
  br i1 %151, label %152, label %156

152:                                              ; preds = %149
  %153 = load ptr, ptr %6, align 8
  %154 = getelementptr inbounds %struct.cJSON, ptr %153, i32 0, i32 2
  %155 = load ptr, ptr %154, align 8
  br label %157

156:                                              ; preds = %149
  br label %157

157:                                              ; preds = %156, %152
  %158 = phi ptr [ %155, %152 ], [ null, %156 ]
  store ptr %158, ptr %11, align 8
  br label %159

159:                                              ; preds = %180, %157
  %160 = load ptr, ptr %11, align 8
  %161 = icmp ne ptr %160, null
  br i1 %161, label %162, label %184

162:                                              ; preds = %159
  %163 = load ptr, ptr %5, align 8
  %164 = load ptr, ptr %11, align 8
  %165 = getelementptr inbounds %struct.cJSON, ptr %164, i32 0, i32 7
  %166 = load ptr, ptr %165, align 8
  %167 = load i32, ptr %7, align 4
  %168 = call ptr @get_object_item(ptr noundef %163, ptr noundef %166, i32 noundef %167)
  store ptr %168, ptr %10, align 8
  %169 = load ptr, ptr %10, align 8
  %170 = icmp eq ptr %169, null
  br i1 %170, label %171, label %172

171:                                              ; preds = %162
  store i32 0, ptr %4, align 4
  br label %186

172:                                              ; preds = %162
  %173 = load ptr, ptr %11, align 8
  %174 = load ptr, ptr %10, align 8
  %175 = load i32, ptr %7, align 4
  %176 = call i32 @cJSON_Compare(ptr noundef %173, ptr noundef %174, i32 noundef %175)
  %177 = icmp ne i32 %176, 0
  br i1 %177, label %179, label %178

178:                                              ; preds = %172
  store i32 0, ptr %4, align 4
  br label %186

179:                                              ; preds = %172
  br label %180

180:                                              ; preds = %179
  %181 = load ptr, ptr %11, align 8
  %182 = getelementptr inbounds %struct.cJSON, ptr %181, i32 0, i32 0
  %183 = load ptr, ptr %182, align 8
  store ptr %183, ptr %11, align 8
  br label %159, !llvm.loop !40

184:                                              ; preds = %159
  store i32 1, ptr %4, align 4
  br label %186

185:                                              ; preds = %40
  store i32 0, ptr %4, align 4
  br label %186

186:                                              ; preds = %185, %184, %178, %171, %143, %136, %113, %112, %100, %78, %77, %67, %56, %55, %45, %39, %34, %27
  %187 = load i32, ptr %4, align 4
  ret i32 %187
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSON_malloc(i64 noundef %0) #0 {
  %2 = alloca i64, align 8
  store i64 %0, ptr %2, align 8
  %3 = load ptr, ptr @global_hooks, align 8
  %4 = load i64, ptr %2, align 8
  %5 = call ptr %3(i64 noundef %4)
  ret ptr %5
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_FindPointerFromObjectTo(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store i64 0, ptr %6, align 8
  store ptr null, ptr %7, align 8
  %11 = load ptr, ptr %4, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %16, label %13

13:                                               ; preds = %2
  %14 = load ptr, ptr %5, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %16, label %17

16:                                               ; preds = %13, %2
  store ptr null, ptr %3, align 8
  br label %94

17:                                               ; preds = %13
  %18 = load ptr, ptr %4, align 8
  %19 = load ptr, ptr %5, align 8
  %20 = icmp eq ptr %18, %19
  br i1 %20, label %21, label %23

21:                                               ; preds = %17
  %22 = call ptr @cJSONUtils_strdup(ptr noundef @.str.11)
  store ptr %22, ptr %3, align 8
  br label %94

23:                                               ; preds = %17
  %24 = load ptr, ptr %4, align 8
  %25 = getelementptr inbounds %struct.cJSON, ptr %24, i32 0, i32 2
  %26 = load ptr, ptr %25, align 8
  store ptr %26, ptr %7, align 8
  br label %27

27:                                               ; preds = %87, %23
  %28 = load ptr, ptr %7, align 8
  %29 = icmp ne ptr %28, null
  br i1 %29, label %30, label %93

30:                                               ; preds = %27
  %31 = load ptr, ptr %7, align 8
  %32 = load ptr, ptr %5, align 8
  %33 = call ptr @cJSONUtils_FindPointerFromObjectTo(ptr noundef %31, ptr noundef %32)
  store ptr %33, ptr %8, align 8
  %34 = load ptr, ptr %8, align 8
  %35 = icmp ne ptr %34, null
  br i1 %35, label %36, label %86

36:                                               ; preds = %30
  %37 = load ptr, ptr %4, align 8
  %38 = call i32 @cJSON_IsArray(ptr noundef %37)
  %39 = icmp ne i32 %38, 0
  br i1 %39, label %40, label %58

40:                                               ; preds = %36
  %41 = load ptr, ptr %8, align 8
  %42 = call i64 @strlen(ptr noundef %41) #9
  %43 = add i64 %42, 20
  %44 = add i64 %43, 2
  %45 = call ptr @cJSON_malloc(i64 noundef %44)
  store ptr %45, ptr %9, align 8
  %46 = load i64, ptr %6, align 8
  %47 = icmp ugt i64 %46, -1
  br i1 %47, label %48, label %51

48:                                               ; preds = %40
  %49 = load ptr, ptr %8, align 8
  call void @cJSON_free(ptr noundef %49)
  %50 = load ptr, ptr %9, align 8
  call void @cJSON_free(ptr noundef %50)
  store ptr null, ptr %3, align 8
  br label %94

51:                                               ; preds = %40
  %52 = load ptr, ptr %9, align 8
  %53 = load i64, ptr %6, align 8
  %54 = load ptr, ptr %8, align 8
  %55 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %52, ptr noundef @.str.1.12, i64 noundef %53, ptr noundef %54) #8
  %56 = load ptr, ptr %8, align 8
  call void @cJSON_free(ptr noundef %56)
  %57 = load ptr, ptr %9, align 8
  store ptr %57, ptr %3, align 8
  br label %94

58:                                               ; preds = %36
  %59 = load ptr, ptr %4, align 8
  %60 = call i32 @cJSON_IsObject(ptr noundef %59)
  %61 = icmp ne i32 %60, 0
  br i1 %61, label %62, label %84

62:                                               ; preds = %58
  %63 = load ptr, ptr %8, align 8
  %64 = call i64 @strlen(ptr noundef %63) #9
  %65 = load ptr, ptr %7, align 8
  %66 = getelementptr inbounds %struct.cJSON, ptr %65, i32 0, i32 7
  %67 = load ptr, ptr %66, align 8
  %68 = call i64 @pointer_encoded_length(ptr noundef %67)
  %69 = add i64 %64, %68
  %70 = add i64 %69, 2
  %71 = call ptr @cJSON_malloc(i64 noundef %70)
  store ptr %71, ptr %10, align 8
  %72 = load ptr, ptr %10, align 8
  %73 = getelementptr inbounds i8, ptr %72, i64 0
  store i8 47, ptr %73, align 1
  %74 = load ptr, ptr %10, align 8
  %75 = getelementptr inbounds i8, ptr %74, i64 1
  %76 = load ptr, ptr %7, align 8
  %77 = getelementptr inbounds %struct.cJSON, ptr %76, i32 0, i32 7
  %78 = load ptr, ptr %77, align 8
  call void @encode_string_as_pointer(ptr noundef %75, ptr noundef %78)
  %79 = load ptr, ptr %10, align 8
  %80 = load ptr, ptr %8, align 8
  %81 = call ptr @strcat(ptr noundef %79, ptr noundef %80) #8
  %82 = load ptr, ptr %8, align 8
  call void @cJSON_free(ptr noundef %82)
  %83 = load ptr, ptr %10, align 8
  store ptr %83, ptr %3, align 8
  br label %94

84:                                               ; preds = %58
  %85 = load ptr, ptr %8, align 8
  call void @cJSON_free(ptr noundef %85)
  store ptr null, ptr %3, align 8
  br label %94

86:                                               ; preds = %30
  br label %87

87:                                               ; preds = %86
  %88 = load ptr, ptr %7, align 8
  %89 = getelementptr inbounds %struct.cJSON, ptr %88, i32 0, i32 0
  %90 = load ptr, ptr %89, align 8
  store ptr %90, ptr %7, align 8
  %91 = load i64, ptr %6, align 8
  %92 = add i64 %91, 1
  store i64 %92, ptr %6, align 8
  br label %27, !llvm.loop !41

93:                                               ; preds = %27
  store ptr null, ptr %3, align 8
  br label %94

94:                                               ; preds = %93, %84, %62, %51, %48, %21, %16
  %95 = load ptr, ptr %3, align 8
  ret ptr %95
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @cJSONUtils_strdup(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  %4 = alloca i64, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store i64 0, ptr %4, align 8
  store ptr null, ptr %5, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = call i64 @strlen(ptr noundef %6) #9
  %8 = add i64 %7, 1
  store i64 %8, ptr %4, align 8
  %9 = load i64, ptr %4, align 8
  %10 = call ptr @cJSON_malloc(i64 noundef %9)
  store ptr %10, ptr %5, align 8
  %11 = load ptr, ptr %5, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %1
  store ptr null, ptr %2, align 8
  br label %19

14:                                               ; preds = %1
  %15 = load ptr, ptr %5, align 8
  %16 = load ptr, ptr %3, align 8
  %17 = load i64, ptr %4, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %15, ptr align 1 %16, i64 %17, i1 false)
  %18 = load ptr, ptr %5, align 8
  store ptr %18, ptr %2, align 8
  br label %19

19:                                               ; preds = %14, %13
  %20 = load ptr, ptr %2, align 8
  ret ptr %20
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i64 @pointer_encoded_length(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca i64, align 8
  store ptr %0, ptr %2, align 8
  store i64 0, ptr %3, align 8
  br label %4

4:                                                ; preds = %23, %1
  %5 = load ptr, ptr %2, align 8
  %6 = load i8, ptr %5, align 1
  %7 = zext i8 %6 to i32
  %8 = icmp ne i32 %7, 0
  br i1 %8, label %9, label %28

9:                                                ; preds = %4
  %10 = load ptr, ptr %2, align 8
  %11 = load i8, ptr %10, align 1
  %12 = zext i8 %11 to i32
  %13 = icmp eq i32 %12, 126
  br i1 %13, label %19, label %14

14:                                               ; preds = %9
  %15 = load ptr, ptr %2, align 8
  %16 = load i8, ptr %15, align 1
  %17 = zext i8 %16 to i32
  %18 = icmp eq i32 %17, 47
  br i1 %18, label %19, label %22

19:                                               ; preds = %14, %9
  %20 = load i64, ptr %3, align 8
  %21 = add i64 %20, 1
  store i64 %21, ptr %3, align 8
  br label %22

22:                                               ; preds = %19, %14
  br label %23

23:                                               ; preds = %22
  %24 = load ptr, ptr %2, align 8
  %25 = getelementptr inbounds i8, ptr %24, i32 1
  store ptr %25, ptr %2, align 8
  %26 = load i64, ptr %3, align 8
  %27 = add i64 %26, 1
  store i64 %27, ptr %3, align 8
  br label %4, !llvm.loop !42

28:                                               ; preds = %4
  %29 = load i64, ptr %3, align 8
  ret i64 %29
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @encode_string_as_pointer(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  br label %5

5:                                                ; preds = %45, %2
  %6 = load ptr, ptr %4, align 8
  %7 = getelementptr inbounds i8, ptr %6, i64 0
  %8 = load i8, ptr %7, align 1
  %9 = zext i8 %8 to i32
  %10 = icmp ne i32 %9, 0
  br i1 %10, label %11, label %50

11:                                               ; preds = %5
  %12 = load ptr, ptr %4, align 8
  %13 = getelementptr inbounds i8, ptr %12, i64 0
  %14 = load i8, ptr %13, align 1
  %15 = zext i8 %14 to i32
  %16 = icmp eq i32 %15, 47
  br i1 %16, label %17, label %24

17:                                               ; preds = %11
  %18 = load ptr, ptr %3, align 8
  %19 = getelementptr inbounds i8, ptr %18, i64 0
  store i8 126, ptr %19, align 1
  %20 = load ptr, ptr %3, align 8
  %21 = getelementptr inbounds i8, ptr %20, i64 1
  store i8 49, ptr %21, align 1
  %22 = load ptr, ptr %3, align 8
  %23 = getelementptr inbounds i8, ptr %22, i32 1
  store ptr %23, ptr %3, align 8
  br label %44

24:                                               ; preds = %11
  %25 = load ptr, ptr %4, align 8
  %26 = getelementptr inbounds i8, ptr %25, i64 0
  %27 = load i8, ptr %26, align 1
  %28 = zext i8 %27 to i32
  %29 = icmp eq i32 %28, 126
  br i1 %29, label %30, label %37

30:                                               ; preds = %24
  %31 = load ptr, ptr %3, align 8
  %32 = getelementptr inbounds i8, ptr %31, i64 0
  store i8 126, ptr %32, align 1
  %33 = load ptr, ptr %3, align 8
  %34 = getelementptr inbounds i8, ptr %33, i64 1
  store i8 48, ptr %34, align 1
  %35 = load ptr, ptr %3, align 8
  %36 = getelementptr inbounds i8, ptr %35, i32 1
  store ptr %36, ptr %3, align 8
  br label %43

37:                                               ; preds = %24
  %38 = load ptr, ptr %4, align 8
  %39 = getelementptr inbounds i8, ptr %38, i64 0
  %40 = load i8, ptr %39, align 1
  %41 = load ptr, ptr %3, align 8
  %42 = getelementptr inbounds i8, ptr %41, i64 0
  store i8 %40, ptr %42, align 1
  br label %43

43:                                               ; preds = %37, %30
  br label %44

44:                                               ; preds = %43, %17
  br label %45

45:                                               ; preds = %44
  %46 = load ptr, ptr %4, align 8
  %47 = getelementptr inbounds i8, ptr %46, i32 1
  store ptr %47, ptr %4, align 8
  %48 = load ptr, ptr %3, align 8
  %49 = getelementptr inbounds i8, ptr %48, i32 1
  store ptr %49, ptr %3, align 8
  br label %5, !llvm.loop !43

50:                                               ; preds = %5
  %51 = load ptr, ptr %3, align 8
  %52 = getelementptr inbounds i8, ptr %51, i64 0
  store i8 0, ptr %52, align 1
  ret void
}

; Function Attrs: nounwind
declare ptr @strcat(ptr noundef, ptr noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GetPointer(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @get_item_from_pointer(ptr noundef %5, ptr noundef %6, i32 noundef 0)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @get_item_from_pointer(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  %9 = alloca i64, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %10 = load ptr, ptr %5, align 8
  store ptr %10, ptr %8, align 8
  %11 = load ptr, ptr %6, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %3
  store ptr null, ptr %4, align 8
  br label %91

14:                                               ; preds = %3
  br label %15

15:                                               ; preds = %88, %14
  %16 = load ptr, ptr %6, align 8
  %17 = getelementptr inbounds i8, ptr %16, i64 0
  %18 = load i8, ptr %17, align 1
  %19 = zext i8 %18 to i32
  %20 = icmp eq i32 %19, 47
  br i1 %20, label %21, label %24

21:                                               ; preds = %15
  %22 = load ptr, ptr %8, align 8
  %23 = icmp ne ptr %22, null
  br label %24

24:                                               ; preds = %21, %15
  %25 = phi i1 [ false, %15 ], [ %23, %21 ]
  br i1 %25, label %26, label %89

26:                                               ; preds = %24
  %27 = load ptr, ptr %6, align 8
  %28 = getelementptr inbounds i8, ptr %27, i32 1
  store ptr %28, ptr %6, align 8
  %29 = load ptr, ptr %8, align 8
  %30 = call i32 @cJSON_IsArray(ptr noundef %29)
  %31 = icmp ne i32 %30, 0
  br i1 %31, label %32, label %41

32:                                               ; preds = %26
  store i64 0, ptr %9, align 8
  %33 = load ptr, ptr %6, align 8
  %34 = call i32 @decode_array_index_from_pointer(ptr noundef %33, ptr noundef %9)
  %35 = icmp ne i32 %34, 0
  br i1 %35, label %37, label %36

36:                                               ; preds = %32
  store ptr null, ptr %4, align 8
  br label %91

37:                                               ; preds = %32
  %38 = load ptr, ptr %8, align 8
  %39 = load i64, ptr %9, align 8
  %40 = call ptr @get_array_item.13(ptr noundef %38, i64 noundef %39)
  store ptr %40, ptr %8, align 8
  br label %70

41:                                               ; preds = %26
  %42 = load ptr, ptr %8, align 8
  %43 = call i32 @cJSON_IsObject(ptr noundef %42)
  %44 = icmp ne i32 %43, 0
  br i1 %44, label %45, label %68

45:                                               ; preds = %41
  %46 = load ptr, ptr %8, align 8
  %47 = getelementptr inbounds %struct.cJSON, ptr %46, i32 0, i32 2
  %48 = load ptr, ptr %47, align 8
  store ptr %48, ptr %8, align 8
  br label %49

49:                                               ; preds = %63, %45
  %50 = load ptr, ptr %8, align 8
  %51 = icmp ne ptr %50, null
  br i1 %51, label %52, label %61

52:                                               ; preds = %49
  %53 = load ptr, ptr %8, align 8
  %54 = getelementptr inbounds %struct.cJSON, ptr %53, i32 0, i32 7
  %55 = load ptr, ptr %54, align 8
  %56 = load ptr, ptr %6, align 8
  %57 = load i32, ptr %7, align 4
  %58 = call i32 @compare_pointers(ptr noundef %55, ptr noundef %56, i32 noundef %57)
  %59 = icmp ne i32 %58, 0
  %60 = xor i1 %59, true
  br label %61

61:                                               ; preds = %52, %49
  %62 = phi i1 [ false, %49 ], [ %60, %52 ]
  br i1 %62, label %63, label %67

63:                                               ; preds = %61
  %64 = load ptr, ptr %8, align 8
  %65 = getelementptr inbounds %struct.cJSON, ptr %64, i32 0, i32 0
  %66 = load ptr, ptr %65, align 8
  store ptr %66, ptr %8, align 8
  br label %49, !llvm.loop !44

67:                                               ; preds = %61
  br label %69

68:                                               ; preds = %41
  store ptr null, ptr %4, align 8
  br label %91

69:                                               ; preds = %67
  br label %70

70:                                               ; preds = %69, %37
  br label %71

71:                                               ; preds = %85, %70
  %72 = load ptr, ptr %6, align 8
  %73 = getelementptr inbounds i8, ptr %72, i64 0
  %74 = load i8, ptr %73, align 1
  %75 = zext i8 %74 to i32
  %76 = icmp ne i32 %75, 0
  br i1 %76, label %77, label %83

77:                                               ; preds = %71
  %78 = load ptr, ptr %6, align 8
  %79 = getelementptr inbounds i8, ptr %78, i64 0
  %80 = load i8, ptr %79, align 1
  %81 = zext i8 %80 to i32
  %82 = icmp ne i32 %81, 47
  br label %83

83:                                               ; preds = %77, %71
  %84 = phi i1 [ false, %71 ], [ %82, %77 ]
  br i1 %84, label %85, label %88

85:                                               ; preds = %83
  %86 = load ptr, ptr %6, align 8
  %87 = getelementptr inbounds i8, ptr %86, i32 1
  store ptr %87, ptr %6, align 8
  br label %71, !llvm.loop !45

88:                                               ; preds = %83
  br label %15, !llvm.loop !46

89:                                               ; preds = %24
  %90 = load ptr, ptr %8, align 8
  store ptr %90, ptr %4, align 8
  br label %91

91:                                               ; preds = %89, %68, %36, %13
  %92 = load ptr, ptr %4, align 8
  ret ptr %92
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @decode_array_index_from_pointer(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store i64 0, ptr %6, align 8
  store i64 0, ptr %7, align 8
  %8 = load ptr, ptr %4, align 8
  %9 = getelementptr inbounds i8, ptr %8, i64 0
  %10 = load i8, ptr %9, align 1
  %11 = zext i8 %10 to i32
  %12 = icmp eq i32 %11, 48
  br i1 %12, label %13, label %26

13:                                               ; preds = %2
  %14 = load ptr, ptr %4, align 8
  %15 = getelementptr inbounds i8, ptr %14, i64 1
  %16 = load i8, ptr %15, align 1
  %17 = zext i8 %16 to i32
  %18 = icmp ne i32 %17, 0
  br i1 %18, label %19, label %26

19:                                               ; preds = %13
  %20 = load ptr, ptr %4, align 8
  %21 = getelementptr inbounds i8, ptr %20, i64 1
  %22 = load i8, ptr %21, align 1
  %23 = zext i8 %22 to i32
  %24 = icmp ne i32 %23, 47
  br i1 %24, label %25, label %26

25:                                               ; preds = %19
  store i32 0, ptr %3, align 4
  br label %75

26:                                               ; preds = %19, %13, %2
  store i64 0, ptr %7, align 8
  br label %27

27:                                               ; preds = %54, %26
  %28 = load ptr, ptr %4, align 8
  %29 = load i64, ptr %7, align 8
  %30 = getelementptr inbounds i8, ptr %28, i64 %29
  %31 = load i8, ptr %30, align 1
  %32 = zext i8 %31 to i32
  %33 = icmp sge i32 %32, 48
  br i1 %33, label %34, label %41

34:                                               ; preds = %27
  %35 = load ptr, ptr %4, align 8
  %36 = load i64, ptr %7, align 8
  %37 = getelementptr inbounds i8, ptr %35, i64 %36
  %38 = load i8, ptr %37, align 1
  %39 = zext i8 %38 to i32
  %40 = icmp sle i32 %39, 57
  br label %41

41:                                               ; preds = %34, %27
  %42 = phi i1 [ false, %27 ], [ %40, %34 ]
  br i1 %42, label %43, label %57

43:                                               ; preds = %41
  %44 = load i64, ptr %6, align 8
  %45 = mul i64 10, %44
  %46 = load ptr, ptr %4, align 8
  %47 = load i64, ptr %7, align 8
  %48 = getelementptr inbounds i8, ptr %46, i64 %47
  %49 = load i8, ptr %48, align 1
  %50 = zext i8 %49 to i32
  %51 = sub nsw i32 %50, 48
  %52 = sext i32 %51 to i64
  %53 = add i64 %45, %52
  store i64 %53, ptr %6, align 8
  br label %54

54:                                               ; preds = %43
  %55 = load i64, ptr %7, align 8
  %56 = add i64 %55, 1
  store i64 %56, ptr %7, align 8
  br label %27, !llvm.loop !47

57:                                               ; preds = %41
  %58 = load ptr, ptr %4, align 8
  %59 = load i64, ptr %7, align 8
  %60 = getelementptr inbounds i8, ptr %58, i64 %59
  %61 = load i8, ptr %60, align 1
  %62 = zext i8 %61 to i32
  %63 = icmp ne i32 %62, 0
  br i1 %63, label %64, label %72

64:                                               ; preds = %57
  %65 = load ptr, ptr %4, align 8
  %66 = load i64, ptr %7, align 8
  %67 = getelementptr inbounds i8, ptr %65, i64 %66
  %68 = load i8, ptr %67, align 1
  %69 = zext i8 %68 to i32
  %70 = icmp ne i32 %69, 47
  br i1 %70, label %71, label %72

71:                                               ; preds = %64
  store i32 0, ptr %3, align 4
  br label %75

72:                                               ; preds = %64, %57
  %73 = load i64, ptr %6, align 8
  %74 = load ptr, ptr %5, align 8
  store i64 %73, ptr %74, align 8
  store i32 1, ptr %3, align 4
  br label %75

75:                                               ; preds = %72, %71, %25
  %76 = load i32, ptr %3, align 4
  ret i32 %76
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @get_array_item.13(ptr noundef %0, i64 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i64, align 8
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store i64 %1, ptr %4, align 8
  %6 = load ptr, ptr %3, align 8
  %7 = icmp ne ptr %6, null
  br i1 %7, label %8, label %12

8:                                                ; preds = %2
  %9 = load ptr, ptr %3, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 2
  %11 = load ptr, ptr %10, align 8
  br label %13

12:                                               ; preds = %2
  br label %13

13:                                               ; preds = %12, %8
  %14 = phi ptr [ %11, %8 ], [ null, %12 ]
  store ptr %14, ptr %5, align 8
  br label %15

15:                                               ; preds = %23, %13
  %16 = load ptr, ptr %5, align 8
  %17 = icmp ne ptr %16, null
  br i1 %17, label %18, label %21

18:                                               ; preds = %15
  %19 = load i64, ptr %4, align 8
  %20 = icmp ugt i64 %19, 0
  br label %21

21:                                               ; preds = %18, %15
  %22 = phi i1 [ false, %15 ], [ %20, %18 ]
  br i1 %22, label %23, label %29

23:                                               ; preds = %21
  %24 = load i64, ptr %4, align 8
  %25 = add i64 %24, -1
  store i64 %25, ptr %4, align 8
  %26 = load ptr, ptr %5, align 8
  %27 = getelementptr inbounds %struct.cJSON, ptr %26, i32 0, i32 0
  %28 = load ptr, ptr %27, align 8
  store ptr %28, ptr %5, align 8
  br label %15, !llvm.loop !48

29:                                               ; preds = %21
  %30 = load ptr, ptr %5, align 8
  ret ptr %30
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @compare_pointers(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %8 = load ptr, ptr %5, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %13, label %10

10:                                               ; preds = %3
  %11 = load ptr, ptr %6, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %10, %3
  store i32 0, ptr %4, align 4
  br label %117

14:                                               ; preds = %10
  br label %15

15:                                               ; preds = %91, %14
  %16 = load ptr, ptr %5, align 8
  %17 = load i8, ptr %16, align 1
  %18 = zext i8 %17 to i32
  %19 = icmp ne i32 %18, 0
  br i1 %19, label %20, label %30

20:                                               ; preds = %15
  %21 = load ptr, ptr %6, align 8
  %22 = load i8, ptr %21, align 1
  %23 = zext i8 %22 to i32
  %24 = icmp ne i32 %23, 0
  br i1 %24, label %25, label %30

25:                                               ; preds = %20
  %26 = load ptr, ptr %6, align 8
  %27 = load i8, ptr %26, align 1
  %28 = zext i8 %27 to i32
  %29 = icmp ne i32 %28, 47
  br label %30

30:                                               ; preds = %25, %20, %15
  %31 = phi i1 [ false, %20 ], [ false, %15 ], [ %29, %25 ]
  br i1 %31, label %32, label %96

32:                                               ; preds = %30
  %33 = load ptr, ptr %6, align 8
  %34 = load i8, ptr %33, align 1
  %35 = zext i8 %34 to i32
  %36 = icmp eq i32 %35, 126
  br i1 %36, label %37, label %64

37:                                               ; preds = %32
  %38 = load ptr, ptr %6, align 8
  %39 = getelementptr inbounds i8, ptr %38, i64 1
  %40 = load i8, ptr %39, align 1
  %41 = zext i8 %40 to i32
  %42 = icmp ne i32 %41, 48
  br i1 %42, label %48, label %43

43:                                               ; preds = %37
  %44 = load ptr, ptr %5, align 8
  %45 = load i8, ptr %44, align 1
  %46 = zext i8 %45 to i32
  %47 = icmp ne i32 %46, 126
  br i1 %47, label %48, label %60

48:                                               ; preds = %43, %37
  %49 = load ptr, ptr %6, align 8
  %50 = getelementptr inbounds i8, ptr %49, i64 1
  %51 = load i8, ptr %50, align 1
  %52 = zext i8 %51 to i32
  %53 = icmp ne i32 %52, 49
  br i1 %53, label %59, label %54

54:                                               ; preds = %48
  %55 = load ptr, ptr %5, align 8
  %56 = load i8, ptr %55, align 1
  %57 = zext i8 %56 to i32
  %58 = icmp ne i32 %57, 47
  br i1 %58, label %59, label %60

59:                                               ; preds = %54, %48
  store i32 0, ptr %4, align 4
  br label %117

60:                                               ; preds = %54, %43
  %61 = load ptr, ptr %6, align 8
  %62 = getelementptr inbounds i8, ptr %61, i32 1
  store ptr %62, ptr %6, align 8
  br label %63

63:                                               ; preds = %60
  br label %90

64:                                               ; preds = %32
  %65 = load i32, ptr %7, align 4
  %66 = icmp ne i32 %65, 0
  br i1 %66, label %77, label %67

67:                                               ; preds = %64
  %68 = load ptr, ptr %5, align 8
  %69 = load i8, ptr %68, align 1
  %70 = zext i8 %69 to i32
  %71 = call i32 @tolower(i32 noundef %70) #9
  %72 = load ptr, ptr %6, align 8
  %73 = load i8, ptr %72, align 1
  %74 = zext i8 %73 to i32
  %75 = call i32 @tolower(i32 noundef %74) #9
  %76 = icmp ne i32 %71, %75
  br i1 %76, label %88, label %77

77:                                               ; preds = %67, %64
  %78 = load i32, ptr %7, align 4
  %79 = icmp ne i32 %78, 0
  br i1 %79, label %80, label %89

80:                                               ; preds = %77
  %81 = load ptr, ptr %5, align 8
  %82 = load i8, ptr %81, align 1
  %83 = zext i8 %82 to i32
  %84 = load ptr, ptr %6, align 8
  %85 = load i8, ptr %84, align 1
  %86 = zext i8 %85 to i32
  %87 = icmp ne i32 %83, %86
  br i1 %87, label %88, label %89

88:                                               ; preds = %80, %67
  store i32 0, ptr %4, align 4
  br label %117

89:                                               ; preds = %80, %77
  br label %90

90:                                               ; preds = %89, %63
  br label %91

91:                                               ; preds = %90
  %92 = load ptr, ptr %5, align 8
  %93 = getelementptr inbounds i8, ptr %92, i32 1
  store ptr %93, ptr %5, align 8
  %94 = load ptr, ptr %6, align 8
  %95 = getelementptr inbounds i8, ptr %94, i32 1
  store ptr %95, ptr %6, align 8
  br label %15, !llvm.loop !49

96:                                               ; preds = %30
  %97 = load ptr, ptr %6, align 8
  %98 = load i8, ptr %97, align 1
  %99 = zext i8 %98 to i32
  %100 = icmp ne i32 %99, 0
  br i1 %100, label %101, label %106

101:                                              ; preds = %96
  %102 = load ptr, ptr %6, align 8
  %103 = load i8, ptr %102, align 1
  %104 = zext i8 %103 to i32
  %105 = icmp ne i32 %104, 47
  br label %106

106:                                              ; preds = %101, %96
  %107 = phi i1 [ false, %96 ], [ %105, %101 ]
  %108 = zext i1 %107 to i32
  %109 = load ptr, ptr %5, align 8
  %110 = load i8, ptr %109, align 1
  %111 = zext i8 %110 to i32
  %112 = icmp ne i32 %111, 0
  %113 = zext i1 %112 to i32
  %114 = icmp ne i32 %108, %113
  br i1 %114, label %115, label %116

115:                                              ; preds = %106
  store i32 0, ptr %4, align 4
  br label %117

116:                                              ; preds = %106
  store i32 1, ptr %4, align 4
  br label %117

117:                                              ; preds = %116, %115, %88, %59, %13
  %118 = load i32, ptr %4, align 4
  ret i32 %118
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GetPointerCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @get_item_from_pointer(ptr noundef %5, ptr noundef %6, i32 noundef 1)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSONUtils_ApplyPatches(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store i32 0, ptr %7, align 4
  %8 = load ptr, ptr %5, align 8
  %9 = call i32 @cJSON_IsArray(ptr noundef %8)
  %10 = icmp ne i32 %9, 0
  br i1 %10, label %12, label %11

11:                                               ; preds = %2
  store i32 1, ptr %3, align 4
  br label %36

12:                                               ; preds = %2
  %13 = load ptr, ptr %5, align 8
  %14 = icmp ne ptr %13, null
  br i1 %14, label %15, label %19

15:                                               ; preds = %12
  %16 = load ptr, ptr %5, align 8
  %17 = getelementptr inbounds %struct.cJSON, ptr %16, i32 0, i32 2
  %18 = load ptr, ptr %17, align 8
  store ptr %18, ptr %6, align 8
  br label %19

19:                                               ; preds = %15, %12
  br label %20

20:                                               ; preds = %31, %19
  %21 = load ptr, ptr %6, align 8
  %22 = icmp ne ptr %21, null
  br i1 %22, label %23, label %35

23:                                               ; preds = %20
  %24 = load ptr, ptr %4, align 8
  %25 = load ptr, ptr %6, align 8
  %26 = call i32 @apply_patch(ptr noundef %24, ptr noundef %25, i32 noundef 0)
  store i32 %26, ptr %7, align 4
  %27 = load i32, ptr %7, align 4
  %28 = icmp ne i32 %27, 0
  br i1 %28, label %29, label %31

29:                                               ; preds = %23
  %30 = load i32, ptr %7, align 4
  store i32 %30, ptr %3, align 4
  br label %36

31:                                               ; preds = %23
  %32 = load ptr, ptr %6, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 0
  %34 = load ptr, ptr %33, align 8
  store ptr %34, ptr %6, align 8
  br label %20, !llvm.loop !50

35:                                               ; preds = %20
  store i32 0, ptr %3, align 4
  br label %36

36:                                               ; preds = %35, %29, %11
  %37 = load i32, ptr %3, align 4
  ret i32 %37
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @apply_patch(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca i32, align 4
  %11 = alloca ptr, align 8
  %12 = alloca ptr, align 8
  %13 = alloca i32, align 4
  %14 = alloca %struct.cJSON, align 8
  %15 = alloca %struct.cJSON, align 8
  %16 = alloca ptr, align 8
  %17 = alloca ptr, align 8
  %18 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store i32 %2, ptr %6, align 4
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  store i32 0, ptr %10, align 4
  store ptr null, ptr %11, align 8
  store ptr null, ptr %12, align 8
  store i32 0, ptr %13, align 4
  %19 = load ptr, ptr %5, align 8
  %20 = load i32, ptr %6, align 4
  %21 = call ptr @get_object_item.15(ptr noundef %19, ptr noundef @.str.2.14, i32 noundef %20)
  store ptr %21, ptr %7, align 8
  %22 = load ptr, ptr %7, align 8
  %23 = call i32 @cJSON_IsString(ptr noundef %22)
  %24 = icmp ne i32 %23, 0
  br i1 %24, label %26, label %25

25:                                               ; preds = %3
  store i32 2, ptr %13, align 4
  br label %262

26:                                               ; preds = %3
  %27 = load ptr, ptr %5, align 8
  %28 = load i32, ptr %6, align 4
  %29 = call i32 @decode_patch_operation(ptr noundef %27, i32 noundef %28)
  store i32 %29, ptr %10, align 4
  %30 = load i32, ptr %10, align 4
  %31 = icmp eq i32 %30, 0
  br i1 %31, label %32, label %33

32:                                               ; preds = %26
  store i32 3, ptr %13, align 4
  br label %262

33:                                               ; preds = %26
  %34 = load i32, ptr %10, align 4
  %35 = icmp eq i32 %34, 6
  br i1 %35, label %36, label %51

36:                                               ; preds = %33
  %37 = load ptr, ptr %4, align 8
  %38 = load ptr, ptr %7, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 4
  %40 = load ptr, ptr %39, align 8
  %41 = load i32, ptr %6, align 4
  %42 = call ptr @get_item_from_pointer(ptr noundef %37, ptr noundef %40, i32 noundef %41)
  %43 = load ptr, ptr %5, align 8
  %44 = load i32, ptr %6, align 4
  %45 = call ptr @get_object_item.15(ptr noundef %43, ptr noundef @.str.3.16, i32 noundef %44)
  %46 = load i32, ptr %6, align 4
  %47 = call i32 @compare_json(ptr noundef %42, ptr noundef %45, i32 noundef %46)
  %48 = icmp ne i32 %47, 0
  %49 = xor i1 %48, true
  %50 = zext i1 %49 to i32
  store i32 %50, ptr %13, align 4
  br label %262

51:                                               ; preds = %33
  br label %52

52:                                               ; preds = %51
  %53 = load ptr, ptr %7, align 8
  %54 = getelementptr inbounds %struct.cJSON, ptr %53, i32 0, i32 4
  %55 = load ptr, ptr %54, align 8
  %56 = getelementptr inbounds i8, ptr %55, i64 0
  %57 = load i8, ptr %56, align 1
  %58 = zext i8 %57 to i32
  %59 = icmp eq i32 %58, 0
  br i1 %59, label %60, label %100

60:                                               ; preds = %52
  %61 = load i32, ptr %10, align 4
  %62 = icmp eq i32 %61, 2
  br i1 %62, label %63, label %65

63:                                               ; preds = %60
  %64 = load ptr, ptr %4, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %14, ptr align 8 @apply_patch.invalid, i64 64, i1 false)
  call void @overwrite_item(ptr noundef %64, ptr noundef %14)
  store i32 0, ptr %13, align 4
  br label %262

65:                                               ; preds = %60
  %66 = load i32, ptr %10, align 4
  %67 = icmp eq i32 %66, 3
  br i1 %67, label %71, label %68

68:                                               ; preds = %65
  %69 = load i32, ptr %10, align 4
  %70 = icmp eq i32 %69, 1
  br i1 %70, label %71, label %99

71:                                               ; preds = %68, %65
  %72 = load ptr, ptr %5, align 8
  %73 = load i32, ptr %6, align 4
  %74 = call ptr @get_object_item.15(ptr noundef %72, ptr noundef @.str.3.16, i32 noundef %73)
  store ptr %74, ptr %8, align 8
  %75 = load ptr, ptr %8, align 8
  %76 = icmp eq ptr %75, null
  br i1 %76, label %77, label %78

77:                                               ; preds = %71
  store i32 7, ptr %13, align 4
  br label %262

78:                                               ; preds = %71
  %79 = load ptr, ptr %8, align 8
  %80 = call ptr @cJSON_Duplicate(ptr noundef %79, i32 noundef 1)
  store ptr %80, ptr %8, align 8
  %81 = load ptr, ptr %8, align 8
  %82 = icmp eq ptr %81, null
  br i1 %82, label %83, label %84

83:                                               ; preds = %78
  store i32 8, ptr %13, align 4
  br label %262

84:                                               ; preds = %78
  %85 = load ptr, ptr %4, align 8
  %86 = load ptr, ptr %8, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %15, ptr align 8 %86, i64 64, i1 false)
  call void @overwrite_item(ptr noundef %85, ptr noundef %15)
  %87 = load ptr, ptr %8, align 8
  call void @cJSON_free(ptr noundef %87)
  store ptr null, ptr %8, align 8
  %88 = load ptr, ptr %4, align 8
  %89 = getelementptr inbounds %struct.cJSON, ptr %88, i32 0, i32 7
  %90 = load ptr, ptr %89, align 8
  %91 = icmp ne ptr %90, null
  br i1 %91, label %92, label %98

92:                                               ; preds = %84
  %93 = load ptr, ptr %4, align 8
  %94 = getelementptr inbounds %struct.cJSON, ptr %93, i32 0, i32 7
  %95 = load ptr, ptr %94, align 8
  call void @cJSON_free(ptr noundef %95)
  %96 = load ptr, ptr %4, align 8
  %97 = getelementptr inbounds %struct.cJSON, ptr %96, i32 0, i32 7
  store ptr null, ptr %97, align 8
  br label %98

98:                                               ; preds = %92, %84
  store i32 0, ptr %13, align 4
  br label %262

99:                                               ; preds = %68
  br label %100

100:                                              ; preds = %99, %52
  %101 = load i32, ptr %10, align 4
  %102 = icmp eq i32 %101, 2
  br i1 %102, label %106, label %103

103:                                              ; preds = %100
  %104 = load i32, ptr %10, align 4
  %105 = icmp eq i32 %104, 3
  br i1 %105, label %106, label %122

106:                                              ; preds = %103, %100
  %107 = load ptr, ptr %4, align 8
  %108 = load ptr, ptr %7, align 8
  %109 = getelementptr inbounds %struct.cJSON, ptr %108, i32 0, i32 4
  %110 = load ptr, ptr %109, align 8
  %111 = load i32, ptr %6, align 4
  %112 = call ptr @detach_path(ptr noundef %107, ptr noundef %110, i32 noundef %111)
  store ptr %112, ptr %16, align 8
  %113 = load ptr, ptr %16, align 8
  %114 = icmp eq ptr %113, null
  br i1 %114, label %115, label %116

115:                                              ; preds = %106
  store i32 13, ptr %13, align 4
  br label %262

116:                                              ; preds = %106
  %117 = load ptr, ptr %16, align 8
  call void @cJSON_Delete(ptr noundef %117)
  %118 = load i32, ptr %10, align 4
  %119 = icmp eq i32 %118, 2
  br i1 %119, label %120, label %121

120:                                              ; preds = %116
  store i32 0, ptr %13, align 4
  br label %262

121:                                              ; preds = %116
  br label %122

122:                                              ; preds = %121, %103
  %123 = load i32, ptr %10, align 4
  %124 = icmp eq i32 %123, 4
  br i1 %124, label %128, label %125

125:                                              ; preds = %122
  %126 = load i32, ptr %10, align 4
  %127 = icmp eq i32 %126, 5
  br i1 %127, label %128, label %170

128:                                              ; preds = %125, %122
  %129 = load ptr, ptr %5, align 8
  %130 = load i32, ptr %6, align 4
  %131 = call ptr @get_object_item.15(ptr noundef %129, ptr noundef @.str.4.17, i32 noundef %130)
  store ptr %131, ptr %17, align 8
  %132 = load ptr, ptr %17, align 8
  %133 = icmp eq ptr %132, null
  br i1 %133, label %134, label %135

134:                                              ; preds = %128
  store i32 4, ptr %13, align 4
  br label %262

135:                                              ; preds = %128
  %136 = load i32, ptr %10, align 4
  %137 = icmp eq i32 %136, 4
  br i1 %137, label %138, label %145

138:                                              ; preds = %135
  %139 = load ptr, ptr %4, align 8
  %140 = load ptr, ptr %17, align 8
  %141 = getelementptr inbounds %struct.cJSON, ptr %140, i32 0, i32 4
  %142 = load ptr, ptr %141, align 8
  %143 = load i32, ptr %6, align 4
  %144 = call ptr @detach_path(ptr noundef %139, ptr noundef %142, i32 noundef %143)
  store ptr %144, ptr %8, align 8
  br label %145

145:                                              ; preds = %138, %135
  %146 = load i32, ptr %10, align 4
  %147 = icmp eq i32 %146, 5
  br i1 %147, label %148, label %155

148:                                              ; preds = %145
  %149 = load ptr, ptr %4, align 8
  %150 = load ptr, ptr %17, align 8
  %151 = getelementptr inbounds %struct.cJSON, ptr %150, i32 0, i32 4
  %152 = load ptr, ptr %151, align 8
  %153 = load i32, ptr %6, align 4
  %154 = call ptr @get_item_from_pointer(ptr noundef %149, ptr noundef %152, i32 noundef %153)
  store ptr %154, ptr %8, align 8
  br label %155

155:                                              ; preds = %148, %145
  %156 = load ptr, ptr %8, align 8
  %157 = icmp eq ptr %156, null
  br i1 %157, label %158, label %159

158:                                              ; preds = %155
  store i32 5, ptr %13, align 4
  br label %262

159:                                              ; preds = %155
  %160 = load i32, ptr %10, align 4
  %161 = icmp eq i32 %160, 5
  br i1 %161, label %162, label %165

162:                                              ; preds = %159
  %163 = load ptr, ptr %8, align 8
  %164 = call ptr @cJSON_Duplicate(ptr noundef %163, i32 noundef 1)
  store ptr %164, ptr %8, align 8
  br label %165

165:                                              ; preds = %162, %159
  %166 = load ptr, ptr %8, align 8
  %167 = icmp eq ptr %166, null
  br i1 %167, label %168, label %169

168:                                              ; preds = %165
  store i32 6, ptr %13, align 4
  br label %262

169:                                              ; preds = %165
  br label %184

170:                                              ; preds = %125
  %171 = load ptr, ptr %5, align 8
  %172 = load i32, ptr %6, align 4
  %173 = call ptr @get_object_item.15(ptr noundef %171, ptr noundef @.str.3.16, i32 noundef %172)
  store ptr %173, ptr %8, align 8
  %174 = load ptr, ptr %8, align 8
  %175 = icmp eq ptr %174, null
  br i1 %175, label %176, label %177

176:                                              ; preds = %170
  store i32 7, ptr %13, align 4
  br label %262

177:                                              ; preds = %170
  %178 = load ptr, ptr %8, align 8
  %179 = call ptr @cJSON_Duplicate(ptr noundef %178, i32 noundef 1)
  store ptr %179, ptr %8, align 8
  %180 = load ptr, ptr %8, align 8
  %181 = icmp eq ptr %180, null
  br i1 %181, label %182, label %183

182:                                              ; preds = %177
  store i32 8, ptr %13, align 4
  br label %262

183:                                              ; preds = %177
  br label %184

184:                                              ; preds = %183, %169
  %185 = load ptr, ptr %7, align 8
  %186 = getelementptr inbounds %struct.cJSON, ptr %185, i32 0, i32 4
  %187 = load ptr, ptr %186, align 8
  %188 = call ptr @cJSONUtils_strdup(ptr noundef %187)
  store ptr %188, ptr %11, align 8
  %189 = load ptr, ptr %11, align 8
  %190 = icmp ne ptr %189, null
  br i1 %190, label %191, label %194

191:                                              ; preds = %184
  %192 = load ptr, ptr %11, align 8
  %193 = call ptr @strrchr(ptr noundef %192, i32 noundef 47) #9
  store ptr %193, ptr %12, align 8
  br label %194

194:                                              ; preds = %191, %184
  %195 = load ptr, ptr %12, align 8
  %196 = icmp ne ptr %195, null
  br i1 %196, label %197, label %202

197:                                              ; preds = %194
  %198 = load ptr, ptr %12, align 8
  %199 = getelementptr inbounds i8, ptr %198, i64 0
  store i8 0, ptr %199, align 1
  %200 = load ptr, ptr %12, align 8
  %201 = getelementptr inbounds i8, ptr %200, i32 1
  store ptr %201, ptr %12, align 8
  br label %202

202:                                              ; preds = %197, %194
  %203 = load ptr, ptr %4, align 8
  %204 = load ptr, ptr %11, align 8
  %205 = load i32, ptr %6, align 4
  %206 = call ptr @get_item_from_pointer(ptr noundef %203, ptr noundef %204, i32 noundef %205)
  store ptr %206, ptr %9, align 8
  %207 = load ptr, ptr %12, align 8
  call void @decode_pointer_inplace(ptr noundef %207)
  %208 = load ptr, ptr %9, align 8
  %209 = icmp eq ptr %208, null
  br i1 %209, label %213, label %210

210:                                              ; preds = %202
  %211 = load ptr, ptr %12, align 8
  %212 = icmp eq ptr %211, null
  br i1 %212, label %213, label %214

213:                                              ; preds = %210, %202
  store i32 9, ptr %13, align 4
  br label %262

214:                                              ; preds = %210
  %215 = load ptr, ptr %9, align 8
  %216 = call i32 @cJSON_IsArray(ptr noundef %215)
  %217 = icmp ne i32 %216, 0
  br i1 %217, label %218, label %240

218:                                              ; preds = %214
  %219 = load ptr, ptr %12, align 8
  %220 = call i32 @strcmp(ptr noundef %219, ptr noundef @.str.5.18) #9
  %221 = icmp eq i32 %220, 0
  br i1 %221, label %222, label %226

222:                                              ; preds = %218
  %223 = load ptr, ptr %9, align 8
  %224 = load ptr, ptr %8, align 8
  %225 = call i32 @cJSON_AddItemToArray(ptr noundef %223, ptr noundef %224)
  store ptr null, ptr %8, align 8
  br label %239

226:                                              ; preds = %218
  store i64 0, ptr %18, align 8
  %227 = load ptr, ptr %12, align 8
  %228 = call i32 @decode_array_index_from_pointer(ptr noundef %227, ptr noundef %18)
  %229 = icmp ne i32 %228, 0
  br i1 %229, label %231, label %230

230:                                              ; preds = %226
  store i32 11, ptr %13, align 4
  br label %262

231:                                              ; preds = %226
  %232 = load ptr, ptr %9, align 8
  %233 = load i64, ptr %18, align 8
  %234 = load ptr, ptr %8, align 8
  %235 = call i32 @insert_item_in_array(ptr noundef %232, i64 noundef %233, ptr noundef %234)
  %236 = icmp ne i32 %235, 0
  br i1 %236, label %238, label %237

237:                                              ; preds = %231
  store i32 10, ptr %13, align 4
  br label %262

238:                                              ; preds = %231
  store ptr null, ptr %8, align 8
  br label %239

239:                                              ; preds = %238, %222
  br label %260

240:                                              ; preds = %214
  %241 = load ptr, ptr %9, align 8
  %242 = call i32 @cJSON_IsObject(ptr noundef %241)
  %243 = icmp ne i32 %242, 0
  br i1 %243, label %244, label %258

244:                                              ; preds = %240
  %245 = load i32, ptr %6, align 4
  %246 = icmp ne i32 %245, 0
  br i1 %246, label %247, label %250

247:                                              ; preds = %244
  %248 = load ptr, ptr %9, align 8
  %249 = load ptr, ptr %12, align 8
  call void @cJSON_DeleteItemFromObjectCaseSensitive(ptr noundef %248, ptr noundef %249)
  br label %253

250:                                              ; preds = %244
  %251 = load ptr, ptr %9, align 8
  %252 = load ptr, ptr %12, align 8
  call void @cJSON_DeleteItemFromObject(ptr noundef %251, ptr noundef %252)
  br label %253

253:                                              ; preds = %250, %247
  %254 = load ptr, ptr %9, align 8
  %255 = load ptr, ptr %12, align 8
  %256 = load ptr, ptr %8, align 8
  %257 = call i32 @cJSON_AddItemToObject(ptr noundef %254, ptr noundef %255, ptr noundef %256)
  store ptr null, ptr %8, align 8
  br label %259

258:                                              ; preds = %240
  store i32 9, ptr %13, align 4
  br label %262

259:                                              ; preds = %253
  br label %260

260:                                              ; preds = %259, %239
  br label %261

261:                                              ; preds = %260
  br label %262

262:                                              ; preds = %261, %258, %237, %230, %213, %182, %176, %168, %158, %134, %120, %115, %98, %83, %77, %63, %36, %32, %25
  %263 = load ptr, ptr %8, align 8
  %264 = icmp ne ptr %263, null
  br i1 %264, label %265, label %267

265:                                              ; preds = %262
  %266 = load ptr, ptr %8, align 8
  call void @cJSON_Delete(ptr noundef %266)
  br label %267

267:                                              ; preds = %265, %262
  %268 = load ptr, ptr %11, align 8
  %269 = icmp ne ptr %268, null
  br i1 %269, label %270, label %272

270:                                              ; preds = %267
  %271 = load ptr, ptr %11, align 8
  call void @cJSON_free(ptr noundef %271)
  br label %272

272:                                              ; preds = %270, %267
  %273 = load i32, ptr %13, align 4
  ret i32 %273
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @get_object_item.15(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %8 = load i32, ptr %7, align 4
  %9 = icmp ne i32 %8, 0
  br i1 %9, label %10, label %14

10:                                               ; preds = %3
  %11 = load ptr, ptr %5, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = call ptr @cJSON_GetObjectItemCaseSensitive(ptr noundef %11, ptr noundef %12)
  store ptr %13, ptr %4, align 8
  br label %18

14:                                               ; preds = %3
  %15 = load ptr, ptr %5, align 8
  %16 = load ptr, ptr %6, align 8
  %17 = call ptr @cJSON_GetObjectItem(ptr noundef %15, ptr noundef %16)
  store ptr %17, ptr %4, align 8
  br label %18

18:                                               ; preds = %14, %10
  %19 = load ptr, ptr %4, align 8
  ret ptr %19
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @decode_patch_operation(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  %7 = load ptr, ptr %4, align 8
  %8 = load i32, ptr %5, align 4
  %9 = call ptr @get_object_item.15(ptr noundef %7, ptr noundef @.str.6.20, i32 noundef %8)
  store ptr %9, ptr %6, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = call i32 @cJSON_IsString(ptr noundef %10)
  %12 = icmp ne i32 %11, 0
  br i1 %12, label %14, label %13

13:                                               ; preds = %2
  store i32 0, ptr %3, align 4
  br label %57

14:                                               ; preds = %2
  %15 = load ptr, ptr %6, align 8
  %16 = getelementptr inbounds %struct.cJSON, ptr %15, i32 0, i32 4
  %17 = load ptr, ptr %16, align 8
  %18 = call i32 @strcmp(ptr noundef %17, ptr noundef @.str.7.21) #9
  %19 = icmp eq i32 %18, 0
  br i1 %19, label %20, label %21

20:                                               ; preds = %14
  store i32 1, ptr %3, align 4
  br label %57

21:                                               ; preds = %14
  %22 = load ptr, ptr %6, align 8
  %23 = getelementptr inbounds %struct.cJSON, ptr %22, i32 0, i32 4
  %24 = load ptr, ptr %23, align 8
  %25 = call i32 @strcmp(ptr noundef %24, ptr noundef @.str.8.22) #9
  %26 = icmp eq i32 %25, 0
  br i1 %26, label %27, label %28

27:                                               ; preds = %21
  store i32 2, ptr %3, align 4
  br label %57

28:                                               ; preds = %21
  %29 = load ptr, ptr %6, align 8
  %30 = getelementptr inbounds %struct.cJSON, ptr %29, i32 0, i32 4
  %31 = load ptr, ptr %30, align 8
  %32 = call i32 @strcmp(ptr noundef %31, ptr noundef @.str.9.23) #9
  %33 = icmp eq i32 %32, 0
  br i1 %33, label %34, label %35

34:                                               ; preds = %28
  store i32 3, ptr %3, align 4
  br label %57

35:                                               ; preds = %28
  %36 = load ptr, ptr %6, align 8
  %37 = getelementptr inbounds %struct.cJSON, ptr %36, i32 0, i32 4
  %38 = load ptr, ptr %37, align 8
  %39 = call i32 @strcmp(ptr noundef %38, ptr noundef @.str.10.24) #9
  %40 = icmp eq i32 %39, 0
  br i1 %40, label %41, label %42

41:                                               ; preds = %35
  store i32 4, ptr %3, align 4
  br label %57

42:                                               ; preds = %35
  %43 = load ptr, ptr %6, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 4
  %45 = load ptr, ptr %44, align 8
  %46 = call i32 @strcmp(ptr noundef %45, ptr noundef @.str.11.25) #9
  %47 = icmp eq i32 %46, 0
  br i1 %47, label %48, label %49

48:                                               ; preds = %42
  store i32 5, ptr %3, align 4
  br label %57

49:                                               ; preds = %42
  %50 = load ptr, ptr %6, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 4
  %52 = load ptr, ptr %51, align 8
  %53 = call i32 @strcmp(ptr noundef %52, ptr noundef @.str.12) #9
  %54 = icmp eq i32 %53, 0
  br i1 %54, label %55, label %56

55:                                               ; preds = %49
  store i32 6, ptr %3, align 4
  br label %57

56:                                               ; preds = %49
  store i32 0, ptr %3, align 4
  br label %57

57:                                               ; preds = %56, %55, %48, %41, %34, %27, %20, %13
  %58 = load i32, ptr %3, align 4
  ret i32 %58
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @compare_json(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  %9 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %10 = load ptr, ptr %5, align 8
  %11 = icmp eq ptr %10, null
  br i1 %11, label %25, label %12

12:                                               ; preds = %3
  %13 = load ptr, ptr %6, align 8
  %14 = icmp eq ptr %13, null
  br i1 %14, label %25, label %15

15:                                               ; preds = %12
  %16 = load ptr, ptr %5, align 8
  %17 = getelementptr inbounds %struct.cJSON, ptr %16, i32 0, i32 3
  %18 = load i32, ptr %17, align 8
  %19 = and i32 %18, 255
  %20 = load ptr, ptr %6, align 8
  %21 = getelementptr inbounds %struct.cJSON, ptr %20, i32 0, i32 3
  %22 = load i32, ptr %21, align 8
  %23 = and i32 %22, 255
  %24 = icmp ne i32 %19, %23
  br i1 %24, label %25, label %26

25:                                               ; preds = %15, %12, %3
  store i32 0, ptr %4, align 4
  br label %156

26:                                               ; preds = %15
  %27 = load ptr, ptr %5, align 8
  %28 = getelementptr inbounds %struct.cJSON, ptr %27, i32 0, i32 3
  %29 = load i32, ptr %28, align 8
  %30 = and i32 %29, 255
  switch i32 %30, label %154 [
    i32 8, label %31
    i32 16, label %50
    i32 32, label %61
    i32 64, label %100
  ]

31:                                               ; preds = %26
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 5
  %34 = load i32, ptr %33, align 8
  %35 = load ptr, ptr %6, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 5
  %37 = load i32, ptr %36, align 8
  %38 = icmp ne i32 %34, %37
  br i1 %38, label %48, label %39

39:                                               ; preds = %31
  %40 = load ptr, ptr %5, align 8
  %41 = getelementptr inbounds %struct.cJSON, ptr %40, i32 0, i32 6
  %42 = load double, ptr %41, align 8
  %43 = load ptr, ptr %6, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 6
  %45 = load double, ptr %44, align 8
  %46 = call i32 @compare_double.19(double noundef %42, double noundef %45)
  %47 = icmp ne i32 %46, 0
  br i1 %47, label %49, label %48

48:                                               ; preds = %39, %31
  store i32 0, ptr %4, align 4
  br label %156

49:                                               ; preds = %39
  store i32 1, ptr %4, align 4
  br label %156

50:                                               ; preds = %26
  %51 = load ptr, ptr %5, align 8
  %52 = getelementptr inbounds %struct.cJSON, ptr %51, i32 0, i32 4
  %53 = load ptr, ptr %52, align 8
  %54 = load ptr, ptr %6, align 8
  %55 = getelementptr inbounds %struct.cJSON, ptr %54, i32 0, i32 4
  %56 = load ptr, ptr %55, align 8
  %57 = call i32 @strcmp(ptr noundef %53, ptr noundef %56) #9
  %58 = icmp ne i32 %57, 0
  br i1 %58, label %59, label %60

59:                                               ; preds = %50
  store i32 0, ptr %4, align 4
  br label %156

60:                                               ; preds = %50
  store i32 1, ptr %4, align 4
  br label %156

61:                                               ; preds = %26
  %62 = load ptr, ptr %5, align 8
  %63 = getelementptr inbounds %struct.cJSON, ptr %62, i32 0, i32 2
  %64 = load ptr, ptr %63, align 8
  store ptr %64, ptr %5, align 8
  %65 = load ptr, ptr %6, align 8
  %66 = getelementptr inbounds %struct.cJSON, ptr %65, i32 0, i32 2
  %67 = load ptr, ptr %66, align 8
  store ptr %67, ptr %6, align 8
  br label %68

68:                                               ; preds = %85, %61
  %69 = load ptr, ptr %5, align 8
  %70 = icmp ne ptr %69, null
  br i1 %70, label %71, label %74

71:                                               ; preds = %68
  %72 = load ptr, ptr %6, align 8
  %73 = icmp ne ptr %72, null
  br label %74

74:                                               ; preds = %71, %68
  %75 = phi i1 [ false, %68 ], [ %73, %71 ]
  br i1 %75, label %76, label %92

76:                                               ; preds = %74
  %77 = load ptr, ptr %5, align 8
  %78 = load ptr, ptr %6, align 8
  %79 = load i32, ptr %7, align 4
  %80 = call i32 @compare_json(ptr noundef %77, ptr noundef %78, i32 noundef %79)
  store i32 %80, ptr %8, align 4
  %81 = load i32, ptr %8, align 4
  %82 = icmp ne i32 %81, 0
  br i1 %82, label %84, label %83

83:                                               ; preds = %76
  store i32 0, ptr %4, align 4
  br label %156

84:                                               ; preds = %76
  br label %85

85:                                               ; preds = %84
  %86 = load ptr, ptr %5, align 8
  %87 = getelementptr inbounds %struct.cJSON, ptr %86, i32 0, i32 0
  %88 = load ptr, ptr %87, align 8
  store ptr %88, ptr %5, align 8
  %89 = load ptr, ptr %6, align 8
  %90 = getelementptr inbounds %struct.cJSON, ptr %89, i32 0, i32 0
  %91 = load ptr, ptr %90, align 8
  store ptr %91, ptr %6, align 8
  br label %68, !llvm.loop !51

92:                                               ; preds = %74
  %93 = load ptr, ptr %5, align 8
  %94 = icmp ne ptr %93, null
  br i1 %94, label %98, label %95

95:                                               ; preds = %92
  %96 = load ptr, ptr %6, align 8
  %97 = icmp ne ptr %96, null
  br i1 %97, label %98, label %99

98:                                               ; preds = %95, %92
  store i32 0, ptr %4, align 4
  br label %156

99:                                               ; preds = %95
  store i32 1, ptr %4, align 4
  br label %156

100:                                              ; preds = %26
  %101 = load ptr, ptr %5, align 8
  %102 = load i32, ptr %7, align 4
  call void @sort_object(ptr noundef %101, i32 noundef %102)
  %103 = load ptr, ptr %6, align 8
  %104 = load i32, ptr %7, align 4
  call void @sort_object(ptr noundef %103, i32 noundef %104)
  %105 = load ptr, ptr %5, align 8
  %106 = getelementptr inbounds %struct.cJSON, ptr %105, i32 0, i32 2
  %107 = load ptr, ptr %106, align 8
  store ptr %107, ptr %5, align 8
  %108 = load ptr, ptr %6, align 8
  %109 = getelementptr inbounds %struct.cJSON, ptr %108, i32 0, i32 2
  %110 = load ptr, ptr %109, align 8
  store ptr %110, ptr %6, align 8
  br label %111

111:                                              ; preds = %139, %100
  %112 = load ptr, ptr %5, align 8
  %113 = icmp ne ptr %112, null
  br i1 %113, label %114, label %117

114:                                              ; preds = %111
  %115 = load ptr, ptr %6, align 8
  %116 = icmp ne ptr %115, null
  br label %117

117:                                              ; preds = %114, %111
  %118 = phi i1 [ false, %111 ], [ %116, %114 ]
  br i1 %118, label %119, label %146

119:                                              ; preds = %117
  store i32 0, ptr %9, align 4
  %120 = load ptr, ptr %5, align 8
  %121 = getelementptr inbounds %struct.cJSON, ptr %120, i32 0, i32 7
  %122 = load ptr, ptr %121, align 8
  %123 = load ptr, ptr %6, align 8
  %124 = getelementptr inbounds %struct.cJSON, ptr %123, i32 0, i32 7
  %125 = load ptr, ptr %124, align 8
  %126 = load i32, ptr %7, align 4
  %127 = call i32 @compare_strings(ptr noundef %122, ptr noundef %125, i32 noundef %126)
  %128 = icmp ne i32 %127, 0
  br i1 %128, label %129, label %130

129:                                              ; preds = %119
  store i32 0, ptr %4, align 4
  br label %156

130:                                              ; preds = %119
  %131 = load ptr, ptr %5, align 8
  %132 = load ptr, ptr %6, align 8
  %133 = load i32, ptr %7, align 4
  %134 = call i32 @compare_json(ptr noundef %131, ptr noundef %132, i32 noundef %133)
  store i32 %134, ptr %9, align 4
  %135 = load i32, ptr %9, align 4
  %136 = icmp ne i32 %135, 0
  br i1 %136, label %138, label %137

137:                                              ; preds = %130
  store i32 0, ptr %4, align 4
  br label %156

138:                                              ; preds = %130
  br label %139

139:                                              ; preds = %138
  %140 = load ptr, ptr %5, align 8
  %141 = getelementptr inbounds %struct.cJSON, ptr %140, i32 0, i32 0
  %142 = load ptr, ptr %141, align 8
  store ptr %142, ptr %5, align 8
  %143 = load ptr, ptr %6, align 8
  %144 = getelementptr inbounds %struct.cJSON, ptr %143, i32 0, i32 0
  %145 = load ptr, ptr %144, align 8
  store ptr %145, ptr %6, align 8
  br label %111, !llvm.loop !52

146:                                              ; preds = %117
  %147 = load ptr, ptr %5, align 8
  %148 = icmp ne ptr %147, null
  br i1 %148, label %152, label %149

149:                                              ; preds = %146
  %150 = load ptr, ptr %6, align 8
  %151 = icmp ne ptr %150, null
  br i1 %151, label %152, label %153

152:                                              ; preds = %149, %146
  store i32 0, ptr %4, align 4
  br label %156

153:                                              ; preds = %149
  store i32 1, ptr %4, align 4
  br label %156

154:                                              ; preds = %26
  br label %155

155:                                              ; preds = %154
  store i32 1, ptr %4, align 4
  br label %156

156:                                              ; preds = %155, %153, %152, %137, %129, %99, %98, %83, %60, %59, %49, %48, %25
  %157 = load i32, ptr %4, align 4
  ret i32 %157
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @overwrite_item(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  %4 = load ptr, ptr %3, align 8
  %5 = icmp eq ptr %4, null
  br i1 %5, label %6, label %7

6:                                                ; preds = %2
  br label %36

7:                                                ; preds = %2
  %8 = load ptr, ptr %3, align 8
  %9 = getelementptr inbounds %struct.cJSON, ptr %8, i32 0, i32 7
  %10 = load ptr, ptr %9, align 8
  %11 = icmp ne ptr %10, null
  br i1 %11, label %12, label %16

12:                                               ; preds = %7
  %13 = load ptr, ptr %3, align 8
  %14 = getelementptr inbounds %struct.cJSON, ptr %13, i32 0, i32 7
  %15 = load ptr, ptr %14, align 8
  call void @cJSON_free(ptr noundef %15)
  br label %16

16:                                               ; preds = %12, %7
  %17 = load ptr, ptr %3, align 8
  %18 = getelementptr inbounds %struct.cJSON, ptr %17, i32 0, i32 4
  %19 = load ptr, ptr %18, align 8
  %20 = icmp ne ptr %19, null
  br i1 %20, label %21, label %25

21:                                               ; preds = %16
  %22 = load ptr, ptr %3, align 8
  %23 = getelementptr inbounds %struct.cJSON, ptr %22, i32 0, i32 4
  %24 = load ptr, ptr %23, align 8
  call void @cJSON_free(ptr noundef %24)
  br label %25

25:                                               ; preds = %21, %16
  %26 = load ptr, ptr %3, align 8
  %27 = getelementptr inbounds %struct.cJSON, ptr %26, i32 0, i32 2
  %28 = load ptr, ptr %27, align 8
  %29 = icmp ne ptr %28, null
  br i1 %29, label %30, label %34

30:                                               ; preds = %25
  %31 = load ptr, ptr %3, align 8
  %32 = getelementptr inbounds %struct.cJSON, ptr %31, i32 0, i32 2
  %33 = load ptr, ptr %32, align 8
  call void @cJSON_Delete(ptr noundef %33)
  br label %34

34:                                               ; preds = %30, %25
  %35 = load ptr, ptr %3, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %35, ptr align 8 %1, i64 64, i1 false)
  br label %36

36:                                               ; preds = %34, %6
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @detach_path(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca i32, align 4
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca i64, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store i32 %2, ptr %6, align 4
  store ptr null, ptr %7, align 8
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  store ptr null, ptr %10, align 8
  %12 = load ptr, ptr %5, align 8
  %13 = call ptr @cJSONUtils_strdup(ptr noundef %12)
  store ptr %13, ptr %7, align 8
  %14 = load ptr, ptr %7, align 8
  %15 = icmp eq ptr %14, null
  br i1 %15, label %16, label %17

16:                                               ; preds = %3
  br label %56

17:                                               ; preds = %3
  %18 = load ptr, ptr %7, align 8
  %19 = call ptr @strrchr(ptr noundef %18, i32 noundef 47) #9
  store ptr %19, ptr %8, align 8
  %20 = load ptr, ptr %8, align 8
  %21 = icmp eq ptr %20, null
  br i1 %21, label %22, label %23

22:                                               ; preds = %17
  br label %56

23:                                               ; preds = %17
  %24 = load ptr, ptr %8, align 8
  %25 = getelementptr inbounds i8, ptr %24, i64 0
  store i8 0, ptr %25, align 1
  %26 = load ptr, ptr %8, align 8
  %27 = getelementptr inbounds i8, ptr %26, i32 1
  store ptr %27, ptr %8, align 8
  %28 = load ptr, ptr %4, align 8
  %29 = load ptr, ptr %7, align 8
  %30 = load i32, ptr %6, align 4
  %31 = call ptr @get_item_from_pointer(ptr noundef %28, ptr noundef %29, i32 noundef %30)
  store ptr %31, ptr %9, align 8
  %32 = load ptr, ptr %8, align 8
  call void @decode_pointer_inplace(ptr noundef %32)
  %33 = load ptr, ptr %9, align 8
  %34 = call i32 @cJSON_IsArray(ptr noundef %33)
  %35 = icmp ne i32 %34, 0
  br i1 %35, label %36, label %45

36:                                               ; preds = %23
  store i64 0, ptr %11, align 8
  %37 = load ptr, ptr %8, align 8
  %38 = call i32 @decode_array_index_from_pointer(ptr noundef %37, ptr noundef %11)
  %39 = icmp ne i32 %38, 0
  br i1 %39, label %41, label %40

40:                                               ; preds = %36
  br label %56

41:                                               ; preds = %36
  %42 = load ptr, ptr %9, align 8
  %43 = load i64, ptr %11, align 8
  %44 = call ptr @detach_item_from_array(ptr noundef %42, i64 noundef %43)
  store ptr %44, ptr %10, align 8
  br label %55

45:                                               ; preds = %23
  %46 = load ptr, ptr %9, align 8
  %47 = call i32 @cJSON_IsObject(ptr noundef %46)
  %48 = icmp ne i32 %47, 0
  br i1 %48, label %49, label %53

49:                                               ; preds = %45
  %50 = load ptr, ptr %9, align 8
  %51 = load ptr, ptr %8, align 8
  %52 = call ptr @cJSON_DetachItemFromObject(ptr noundef %50, ptr noundef %51)
  store ptr %52, ptr %10, align 8
  br label %54

53:                                               ; preds = %45
  br label %56

54:                                               ; preds = %49
  br label %55

55:                                               ; preds = %54, %41
  br label %56

56:                                               ; preds = %55, %53, %40, %22, %16
  %57 = load ptr, ptr %7, align 8
  %58 = icmp ne ptr %57, null
  br i1 %58, label %59, label %61

59:                                               ; preds = %56
  %60 = load ptr, ptr %7, align 8
  call void @cJSON_free(ptr noundef %60)
  br label %61

61:                                               ; preds = %59, %56
  %62 = load ptr, ptr %10, align 8
  ret ptr %62
}

; Function Attrs: nounwind willreturn memory(read)
declare ptr @strrchr(ptr noundef, i32 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define internal void @decode_pointer_inplace(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  store ptr %4, ptr %3, align 8
  %5 = load ptr, ptr %2, align 8
  %6 = icmp eq ptr %5, null
  br i1 %6, label %7, label %8

7:                                                ; preds = %1
  br label %51

8:                                                ; preds = %1
  br label %9

9:                                                ; preds = %43, %8
  %10 = load ptr, ptr %2, align 8
  %11 = load i8, ptr %10, align 1
  %12 = icmp ne i8 %11, 0
  br i1 %12, label %13, label %48

13:                                               ; preds = %9
  %14 = load ptr, ptr %2, align 8
  %15 = getelementptr inbounds i8, ptr %14, i64 0
  %16 = load i8, ptr %15, align 1
  %17 = zext i8 %16 to i32
  %18 = icmp eq i32 %17, 126
  br i1 %18, label %19, label %42

19:                                               ; preds = %13
  %20 = load ptr, ptr %2, align 8
  %21 = getelementptr inbounds i8, ptr %20, i64 1
  %22 = load i8, ptr %21, align 1
  %23 = zext i8 %22 to i32
  %24 = icmp eq i32 %23, 48
  br i1 %24, label %25, label %28

25:                                               ; preds = %19
  %26 = load ptr, ptr %3, align 8
  %27 = getelementptr inbounds i8, ptr %26, i64 0
  store i8 126, ptr %27, align 1
  br label %39

28:                                               ; preds = %19
  %29 = load ptr, ptr %2, align 8
  %30 = getelementptr inbounds i8, ptr %29, i64 1
  %31 = load i8, ptr %30, align 1
  %32 = zext i8 %31 to i32
  %33 = icmp eq i32 %32, 49
  br i1 %33, label %34, label %37

34:                                               ; preds = %28
  %35 = load ptr, ptr %3, align 8
  %36 = getelementptr inbounds i8, ptr %35, i64 1
  store i8 47, ptr %36, align 1
  br label %38

37:                                               ; preds = %28
  br label %51

38:                                               ; preds = %34
  br label %39

39:                                               ; preds = %38, %25
  %40 = load ptr, ptr %2, align 8
  %41 = getelementptr inbounds i8, ptr %40, i32 1
  store ptr %41, ptr %2, align 8
  br label %42

42:                                               ; preds = %39, %13
  br label %43

43:                                               ; preds = %42
  %44 = load ptr, ptr %3, align 8
  %45 = getelementptr inbounds i8, ptr %44, i32 1
  store ptr %45, ptr %3, align 8
  %46 = load ptr, ptr %2, align 8
  %47 = getelementptr inbounds i8, ptr %46, i32 1
  store ptr %47, ptr %2, align 8
  br label %9, !llvm.loop !53

48:                                               ; preds = %9
  %49 = load ptr, ptr %3, align 8
  %50 = getelementptr inbounds i8, ptr %49, i64 0
  store i8 0, ptr %50, align 1
  br label %51

51:                                               ; preds = %48, %37, %7
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @insert_item_in_array(ptr noundef %0, i64 noundef %1, ptr noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca i64, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store i64 %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 2
  %11 = load ptr, ptr %10, align 8
  store ptr %11, ptr %8, align 8
  br label %12

12:                                               ; preds = %20, %3
  %13 = load ptr, ptr %8, align 8
  %14 = icmp ne ptr %13, null
  br i1 %14, label %15, label %18

15:                                               ; preds = %12
  %16 = load i64, ptr %6, align 8
  %17 = icmp ugt i64 %16, 0
  br label %18

18:                                               ; preds = %15, %12
  %19 = phi i1 [ false, %12 ], [ %17, %15 ]
  br i1 %19, label %20, label %26

20:                                               ; preds = %18
  %21 = load ptr, ptr %8, align 8
  %22 = getelementptr inbounds %struct.cJSON, ptr %21, i32 0, i32 0
  %23 = load ptr, ptr %22, align 8
  store ptr %23, ptr %8, align 8
  %24 = load i64, ptr %6, align 8
  %25 = add i64 %24, -1
  store i64 %25, ptr %6, align 8
  br label %12, !llvm.loop !54

26:                                               ; preds = %18
  %27 = load i64, ptr %6, align 8
  %28 = icmp ugt i64 %27, 0
  br i1 %28, label %29, label %30

29:                                               ; preds = %26
  store i32 0, ptr %4, align 4
  br label %65

30:                                               ; preds = %26
  %31 = load ptr, ptr %8, align 8
  %32 = icmp eq ptr %31, null
  br i1 %32, label %33, label %37

33:                                               ; preds = %30
  %34 = load ptr, ptr %5, align 8
  %35 = load ptr, ptr %7, align 8
  %36 = call i32 @cJSON_AddItemToArray(ptr noundef %34, ptr noundef %35)
  store i32 1, ptr %4, align 4
  br label %65

37:                                               ; preds = %30
  %38 = load ptr, ptr %8, align 8
  %39 = load ptr, ptr %7, align 8
  %40 = getelementptr inbounds %struct.cJSON, ptr %39, i32 0, i32 0
  store ptr %38, ptr %40, align 8
  %41 = load ptr, ptr %8, align 8
  %42 = getelementptr inbounds %struct.cJSON, ptr %41, i32 0, i32 1
  %43 = load ptr, ptr %42, align 8
  %44 = load ptr, ptr %7, align 8
  %45 = getelementptr inbounds %struct.cJSON, ptr %44, i32 0, i32 1
  store ptr %43, ptr %45, align 8
  %46 = load ptr, ptr %7, align 8
  %47 = load ptr, ptr %8, align 8
  %48 = getelementptr inbounds %struct.cJSON, ptr %47, i32 0, i32 1
  store ptr %46, ptr %48, align 8
  %49 = load ptr, ptr %8, align 8
  %50 = load ptr, ptr %5, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 2
  %52 = load ptr, ptr %51, align 8
  %53 = icmp eq ptr %49, %52
  br i1 %53, label %54, label %58

54:                                               ; preds = %37
  %55 = load ptr, ptr %7, align 8
  %56 = load ptr, ptr %5, align 8
  %57 = getelementptr inbounds %struct.cJSON, ptr %56, i32 0, i32 2
  store ptr %55, ptr %57, align 8
  br label %64

58:                                               ; preds = %37
  %59 = load ptr, ptr %7, align 8
  %60 = load ptr, ptr %7, align 8
  %61 = getelementptr inbounds %struct.cJSON, ptr %60, i32 0, i32 1
  %62 = load ptr, ptr %61, align 8
  %63 = getelementptr inbounds %struct.cJSON, ptr %62, i32 0, i32 0
  store ptr %59, ptr %63, align 8
  br label %64

64:                                               ; preds = %58, %54
  store i32 1, ptr %4, align 4
  br label %65

65:                                               ; preds = %64, %33, %29
  %66 = load i32, ptr %4, align 4
  ret i32 %66
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @detach_item_from_array(ptr noundef %0, i64 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i64, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i64 %1, ptr %5, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = getelementptr inbounds %struct.cJSON, ptr %7, i32 0, i32 2
  %9 = load ptr, ptr %8, align 8
  store ptr %9, ptr %6, align 8
  br label %10

10:                                               ; preds = %18, %2
  %11 = load ptr, ptr %6, align 8
  %12 = icmp ne ptr %11, null
  br i1 %12, label %13, label %16

13:                                               ; preds = %10
  %14 = load i64, ptr %5, align 8
  %15 = icmp ugt i64 %14, 0
  br label %16

16:                                               ; preds = %13, %10
  %17 = phi i1 [ false, %10 ], [ %15, %13 ]
  br i1 %17, label %18, label %24

18:                                               ; preds = %16
  %19 = load ptr, ptr %6, align 8
  %20 = getelementptr inbounds %struct.cJSON, ptr %19, i32 0, i32 0
  %21 = load ptr, ptr %20, align 8
  store ptr %21, ptr %6, align 8
  %22 = load i64, ptr %5, align 8
  %23 = add i64 %22, -1
  store i64 %23, ptr %5, align 8
  br label %10, !llvm.loop !55

24:                                               ; preds = %16
  %25 = load ptr, ptr %6, align 8
  %26 = icmp ne ptr %25, null
  br i1 %26, label %28, label %27

27:                                               ; preds = %24
  store ptr null, ptr %3, align 8
  br label %87

28:                                               ; preds = %24
  %29 = load ptr, ptr %6, align 8
  %30 = load ptr, ptr %4, align 8
  %31 = getelementptr inbounds %struct.cJSON, ptr %30, i32 0, i32 2
  %32 = load ptr, ptr %31, align 8
  %33 = icmp ne ptr %29, %32
  br i1 %33, label %34, label %42

34:                                               ; preds = %28
  %35 = load ptr, ptr %6, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 0
  %37 = load ptr, ptr %36, align 8
  %38 = load ptr, ptr %6, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 1
  %40 = load ptr, ptr %39, align 8
  %41 = getelementptr inbounds %struct.cJSON, ptr %40, i32 0, i32 0
  store ptr %37, ptr %41, align 8
  br label %42

42:                                               ; preds = %34, %28
  %43 = load ptr, ptr %6, align 8
  %44 = getelementptr inbounds %struct.cJSON, ptr %43, i32 0, i32 0
  %45 = load ptr, ptr %44, align 8
  %46 = icmp ne ptr %45, null
  br i1 %46, label %47, label %55

47:                                               ; preds = %42
  %48 = load ptr, ptr %6, align 8
  %49 = getelementptr inbounds %struct.cJSON, ptr %48, i32 0, i32 1
  %50 = load ptr, ptr %49, align 8
  %51 = load ptr, ptr %6, align 8
  %52 = getelementptr inbounds %struct.cJSON, ptr %51, i32 0, i32 0
  %53 = load ptr, ptr %52, align 8
  %54 = getelementptr inbounds %struct.cJSON, ptr %53, i32 0, i32 1
  store ptr %50, ptr %54, align 8
  br label %55

55:                                               ; preds = %47, %42
  %56 = load ptr, ptr %6, align 8
  %57 = load ptr, ptr %4, align 8
  %58 = getelementptr inbounds %struct.cJSON, ptr %57, i32 0, i32 2
  %59 = load ptr, ptr %58, align 8
  %60 = icmp eq ptr %56, %59
  br i1 %60, label %61, label %67

61:                                               ; preds = %55
  %62 = load ptr, ptr %6, align 8
  %63 = getelementptr inbounds %struct.cJSON, ptr %62, i32 0, i32 0
  %64 = load ptr, ptr %63, align 8
  %65 = load ptr, ptr %4, align 8
  %66 = getelementptr inbounds %struct.cJSON, ptr %65, i32 0, i32 2
  store ptr %64, ptr %66, align 8
  br label %81

67:                                               ; preds = %55
  %68 = load ptr, ptr %6, align 8
  %69 = getelementptr inbounds %struct.cJSON, ptr %68, i32 0, i32 0
  %70 = load ptr, ptr %69, align 8
  %71 = icmp eq ptr %70, null
  br i1 %71, label %72, label %80

72:                                               ; preds = %67
  %73 = load ptr, ptr %6, align 8
  %74 = getelementptr inbounds %struct.cJSON, ptr %73, i32 0, i32 1
  %75 = load ptr, ptr %74, align 8
  %76 = load ptr, ptr %4, align 8
  %77 = getelementptr inbounds %struct.cJSON, ptr %76, i32 0, i32 2
  %78 = load ptr, ptr %77, align 8
  %79 = getelementptr inbounds %struct.cJSON, ptr %78, i32 0, i32 1
  store ptr %75, ptr %79, align 8
  br label %80

80:                                               ; preds = %72, %67
  br label %81

81:                                               ; preds = %80, %61
  %82 = load ptr, ptr %6, align 8
  %83 = getelementptr inbounds %struct.cJSON, ptr %82, i32 0, i32 0
  store ptr null, ptr %83, align 8
  %84 = load ptr, ptr %6, align 8
  %85 = getelementptr inbounds %struct.cJSON, ptr %84, i32 0, i32 1
  store ptr null, ptr %85, align 8
  %86 = load ptr, ptr %6, align 8
  store ptr %86, ptr %3, align 8
  br label %87

87:                                               ; preds = %81, %27
  %88 = load ptr, ptr %3, align 8
  ret ptr %88
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @compare_double.19(double noundef %0, double noundef %1) #0 {
  %3 = alloca double, align 8
  %4 = alloca double, align 8
  %5 = alloca double, align 8
  store double %0, ptr %3, align 8
  store double %1, ptr %4, align 8
  %6 = load double, ptr %3, align 8
  %7 = call double @llvm.fabs.f64(double %6)
  %8 = load double, ptr %4, align 8
  %9 = call double @llvm.fabs.f64(double %8)
  %10 = fcmp ogt double %7, %9
  br i1 %10, label %11, label %14

11:                                               ; preds = %2
  %12 = load double, ptr %3, align 8
  %13 = call double @llvm.fabs.f64(double %12)
  br label %17

14:                                               ; preds = %2
  %15 = load double, ptr %4, align 8
  %16 = call double @llvm.fabs.f64(double %15)
  br label %17

17:                                               ; preds = %14, %11
  %18 = phi double [ %13, %11 ], [ %16, %14 ]
  store double %18, ptr %5, align 8
  %19 = load double, ptr %3, align 8
  %20 = load double, ptr %4, align 8
  %21 = fsub double %19, %20
  %22 = call double @llvm.fabs.f64(double %21)
  %23 = load double, ptr %5, align 8
  %24 = fmul double %23, 0x3CB0000000000000
  %25 = fcmp ole double %22, %24
  %26 = zext i1 %25 to i32
  ret i32 %26
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @sort_object(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  store i32 %1, ptr %4, align 4
  %5 = load ptr, ptr %3, align 8
  %6 = icmp eq ptr %5, null
  br i1 %6, label %7, label %8

7:                                                ; preds = %2
  br label %16

8:                                                ; preds = %2
  %9 = load ptr, ptr %3, align 8
  %10 = getelementptr inbounds %struct.cJSON, ptr %9, i32 0, i32 2
  %11 = load ptr, ptr %10, align 8
  %12 = load i32, ptr %4, align 4
  %13 = call ptr @sort_list(ptr noundef %11, i32 noundef %12)
  %14 = load ptr, ptr %3, align 8
  %15 = getelementptr inbounds %struct.cJSON, ptr %14, i32 0, i32 2
  store ptr %13, ptr %15, align 8
  br label %16

16:                                               ; preds = %8, %7
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @compare_strings(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  %8 = load ptr, ptr %5, align 8
  %9 = icmp eq ptr %8, null
  br i1 %9, label %13, label %10

10:                                               ; preds = %3
  %11 = load ptr, ptr %6, align 8
  %12 = icmp eq ptr %11, null
  br i1 %12, label %13, label %14

13:                                               ; preds = %10, %3
  store i32 1, ptr %4, align 4
  br label %59

14:                                               ; preds = %10
  %15 = load ptr, ptr %5, align 8
  %16 = load ptr, ptr %6, align 8
  %17 = icmp eq ptr %15, %16
  br i1 %17, label %18, label %19

18:                                               ; preds = %14
  store i32 0, ptr %4, align 4
  br label %59

19:                                               ; preds = %14
  %20 = load i32, ptr %7, align 4
  %21 = icmp ne i32 %20, 0
  br i1 %21, label %22, label %26

22:                                               ; preds = %19
  %23 = load ptr, ptr %5, align 8
  %24 = load ptr, ptr %6, align 8
  %25 = call i32 @strcmp(ptr noundef %23, ptr noundef %24) #9
  store i32 %25, ptr %4, align 4
  br label %59

26:                                               ; preds = %19
  br label %27

27:                                               ; preds = %44, %26
  %28 = load ptr, ptr %5, align 8
  %29 = load i8, ptr %28, align 1
  %30 = zext i8 %29 to i32
  %31 = call i32 @tolower(i32 noundef %30) #9
  %32 = load ptr, ptr %6, align 8
  %33 = load i8, ptr %32, align 1
  %34 = zext i8 %33 to i32
  %35 = call i32 @tolower(i32 noundef %34) #9
  %36 = icmp eq i32 %31, %35
  br i1 %36, label %37, label %49

37:                                               ; preds = %27
  %38 = load ptr, ptr %5, align 8
  %39 = load i8, ptr %38, align 1
  %40 = zext i8 %39 to i32
  %41 = icmp eq i32 %40, 0
  br i1 %41, label %42, label %43

42:                                               ; preds = %37
  store i32 0, ptr %4, align 4
  br label %59

43:                                               ; preds = %37
  br label %44

44:                                               ; preds = %43
  %45 = load ptr, ptr %5, align 8
  %46 = getelementptr inbounds i8, ptr %45, i32 1
  store ptr %46, ptr %5, align 8
  %47 = load ptr, ptr %6, align 8
  %48 = getelementptr inbounds i8, ptr %47, i32 1
  store ptr %48, ptr %6, align 8
  br label %27, !llvm.loop !56

49:                                               ; preds = %27
  %50 = load ptr, ptr %5, align 8
  %51 = load i8, ptr %50, align 1
  %52 = zext i8 %51 to i32
  %53 = call i32 @tolower(i32 noundef %52) #9
  %54 = load ptr, ptr %6, align 8
  %55 = load i8, ptr %54, align 1
  %56 = zext i8 %55 to i32
  %57 = call i32 @tolower(i32 noundef %56) #9
  %58 = sub nsw i32 %53, %57
  store i32 %58, ptr %4, align 4
  br label %59

59:                                               ; preds = %49, %42, %22, %18, %13
  %60 = load i32, ptr %4, align 4
  ret i32 %60
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @sort_list(ptr noundef %0, i32 noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  %12 = load ptr, ptr %4, align 8
  store ptr %12, ptr %6, align 8
  %13 = load ptr, ptr %4, align 8
  store ptr %13, ptr %7, align 8
  %14 = load ptr, ptr %4, align 8
  store ptr %14, ptr %8, align 8
  %15 = load ptr, ptr %4, align 8
  store ptr %15, ptr %9, align 8
  store ptr null, ptr %10, align 8
  %16 = load ptr, ptr %4, align 8
  %17 = icmp eq ptr %16, null
  br i1 %17, label %23, label %18

18:                                               ; preds = %2
  %19 = load ptr, ptr %4, align 8
  %20 = getelementptr inbounds %struct.cJSON, ptr %19, i32 0, i32 0
  %21 = load ptr, ptr %20, align 8
  %22 = icmp eq ptr %21, null
  br i1 %22, label %23, label %25

23:                                               ; preds = %18, %2
  %24 = load ptr, ptr %9, align 8
  store ptr %24, ptr %3, align 8
  br label %184

25:                                               ; preds = %18
  br label %26

26:                                               ; preds = %48, %25
  %27 = load ptr, ptr %8, align 8
  %28 = icmp ne ptr %27, null
  br i1 %28, label %29, label %46

29:                                               ; preds = %26
  %30 = load ptr, ptr %8, align 8
  %31 = getelementptr inbounds %struct.cJSON, ptr %30, i32 0, i32 0
  %32 = load ptr, ptr %31, align 8
  %33 = icmp ne ptr %32, null
  br i1 %33, label %34, label %46

34:                                               ; preds = %29
  %35 = load ptr, ptr %8, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 7
  %37 = load ptr, ptr %36, align 8
  %38 = load ptr, ptr %8, align 8
  %39 = getelementptr inbounds %struct.cJSON, ptr %38, i32 0, i32 0
  %40 = load ptr, ptr %39, align 8
  %41 = getelementptr inbounds %struct.cJSON, ptr %40, i32 0, i32 7
  %42 = load ptr, ptr %41, align 8
  %43 = load i32, ptr %5, align 4
  %44 = call i32 @compare_strings(ptr noundef %37, ptr noundef %42, i32 noundef %43)
  %45 = icmp slt i32 %44, 0
  br label %46

46:                                               ; preds = %34, %29, %26
  %47 = phi i1 [ false, %29 ], [ false, %26 ], [ %45, %34 ]
  br i1 %47, label %48, label %52

48:                                               ; preds = %46
  %49 = load ptr, ptr %8, align 8
  %50 = getelementptr inbounds %struct.cJSON, ptr %49, i32 0, i32 0
  %51 = load ptr, ptr %50, align 8
  store ptr %51, ptr %8, align 8
  br label %26, !llvm.loop !57

52:                                               ; preds = %46
  %53 = load ptr, ptr %8, align 8
  %54 = icmp eq ptr %53, null
  br i1 %54, label %60, label %55

55:                                               ; preds = %52
  %56 = load ptr, ptr %8, align 8
  %57 = getelementptr inbounds %struct.cJSON, ptr %56, i32 0, i32 0
  %58 = load ptr, ptr %57, align 8
  %59 = icmp eq ptr %58, null
  br i1 %59, label %60, label %62

60:                                               ; preds = %55, %52
  %61 = load ptr, ptr %9, align 8
  store ptr %61, ptr %3, align 8
  br label %184

62:                                               ; preds = %55
  %63 = load ptr, ptr %4, align 8
  store ptr %63, ptr %8, align 8
  br label %64

64:                                               ; preds = %80, %62
  %65 = load ptr, ptr %8, align 8
  %66 = icmp ne ptr %65, null
  br i1 %66, label %67, label %81

67:                                               ; preds = %64
  %68 = load ptr, ptr %7, align 8
  %69 = getelementptr inbounds %struct.cJSON, ptr %68, i32 0, i32 0
  %70 = load ptr, ptr %69, align 8
  store ptr %70, ptr %7, align 8
  %71 = load ptr, ptr %8, align 8
  %72 = getelementptr inbounds %struct.cJSON, ptr %71, i32 0, i32 0
  %73 = load ptr, ptr %72, align 8
  store ptr %73, ptr %8, align 8
  %74 = load ptr, ptr %8, align 8
  %75 = icmp ne ptr %74, null
  br i1 %75, label %76, label %80

76:                                               ; preds = %67
  %77 = load ptr, ptr %8, align 8
  %78 = getelementptr inbounds %struct.cJSON, ptr %77, i32 0, i32 0
  %79 = load ptr, ptr %78, align 8
  store ptr %79, ptr %8, align 8
  br label %80

80:                                               ; preds = %76, %67
  br label %64, !llvm.loop !58

81:                                               ; preds = %64
  %82 = load ptr, ptr %7, align 8
  %83 = icmp ne ptr %82, null
  br i1 %83, label %84, label %96

84:                                               ; preds = %81
  %85 = load ptr, ptr %7, align 8
  %86 = getelementptr inbounds %struct.cJSON, ptr %85, i32 0, i32 1
  %87 = load ptr, ptr %86, align 8
  %88 = icmp ne ptr %87, null
  br i1 %88, label %89, label %96

89:                                               ; preds = %84
  %90 = load ptr, ptr %7, align 8
  %91 = getelementptr inbounds %struct.cJSON, ptr %90, i32 0, i32 1
  %92 = load ptr, ptr %91, align 8
  %93 = getelementptr inbounds %struct.cJSON, ptr %92, i32 0, i32 0
  store ptr null, ptr %93, align 8
  %94 = load ptr, ptr %7, align 8
  %95 = getelementptr inbounds %struct.cJSON, ptr %94, i32 0, i32 1
  store ptr null, ptr %95, align 8
  br label %96

96:                                               ; preds = %89, %84, %81
  %97 = load ptr, ptr %6, align 8
  %98 = load i32, ptr %5, align 4
  %99 = call ptr @sort_list(ptr noundef %97, i32 noundef %98)
  store ptr %99, ptr %6, align 8
  %100 = load ptr, ptr %7, align 8
  %101 = load i32, ptr %5, align 4
  %102 = call ptr @sort_list(ptr noundef %100, i32 noundef %101)
  store ptr %102, ptr %7, align 8
  store ptr null, ptr %9, align 8
  br label %103

103:                                              ; preds = %151, %96
  %104 = load ptr, ptr %6, align 8
  %105 = icmp ne ptr %104, null
  br i1 %105, label %106, label %109

106:                                              ; preds = %103
  %107 = load ptr, ptr %7, align 8
  %108 = icmp ne ptr %107, null
  br label %109

109:                                              ; preds = %106, %103
  %110 = phi i1 [ false, %103 ], [ %108, %106 ]
  br i1 %110, label %111, label %152

111:                                              ; preds = %109
  store ptr null, ptr %11, align 8
  %112 = load ptr, ptr %6, align 8
  %113 = getelementptr inbounds %struct.cJSON, ptr %112, i32 0, i32 7
  %114 = load ptr, ptr %113, align 8
  %115 = load ptr, ptr %7, align 8
  %116 = getelementptr inbounds %struct.cJSON, ptr %115, i32 0, i32 7
  %117 = load ptr, ptr %116, align 8
  %118 = load i32, ptr %5, align 4
  %119 = call i32 @compare_strings(ptr noundef %114, ptr noundef %117, i32 noundef %118)
  %120 = icmp slt i32 %119, 0
  br i1 %120, label %121, label %123

121:                                              ; preds = %111
  %122 = load ptr, ptr %6, align 8
  store ptr %122, ptr %11, align 8
  br label %125

123:                                              ; preds = %111
  %124 = load ptr, ptr %7, align 8
  store ptr %124, ptr %11, align 8
  br label %125

125:                                              ; preds = %123, %121
  %126 = load ptr, ptr %9, align 8
  %127 = icmp eq ptr %126, null
  br i1 %127, label %128, label %131

128:                                              ; preds = %125
  %129 = load ptr, ptr %11, align 8
  store ptr %129, ptr %10, align 8
  %130 = load ptr, ptr %11, align 8
  store ptr %130, ptr %9, align 8
  br label %139

131:                                              ; preds = %125
  %132 = load ptr, ptr %11, align 8
  %133 = load ptr, ptr %10, align 8
  %134 = getelementptr inbounds %struct.cJSON, ptr %133, i32 0, i32 0
  store ptr %132, ptr %134, align 8
  %135 = load ptr, ptr %10, align 8
  %136 = load ptr, ptr %11, align 8
  %137 = getelementptr inbounds %struct.cJSON, ptr %136, i32 0, i32 1
  store ptr %135, ptr %137, align 8
  %138 = load ptr, ptr %11, align 8
  store ptr %138, ptr %10, align 8
  br label %139

139:                                              ; preds = %131, %128
  %140 = load ptr, ptr %6, align 8
  %141 = load ptr, ptr %11, align 8
  %142 = icmp eq ptr %140, %141
  br i1 %142, label %143, label %147

143:                                              ; preds = %139
  %144 = load ptr, ptr %6, align 8
  %145 = getelementptr inbounds %struct.cJSON, ptr %144, i32 0, i32 0
  %146 = load ptr, ptr %145, align 8
  store ptr %146, ptr %6, align 8
  br label %151

147:                                              ; preds = %139
  %148 = load ptr, ptr %7, align 8
  %149 = getelementptr inbounds %struct.cJSON, ptr %148, i32 0, i32 0
  %150 = load ptr, ptr %149, align 8
  store ptr %150, ptr %7, align 8
  br label %151

151:                                              ; preds = %147, %143
  br label %103, !llvm.loop !59

152:                                              ; preds = %109
  %153 = load ptr, ptr %6, align 8
  %154 = icmp ne ptr %153, null
  br i1 %154, label %155, label %167

155:                                              ; preds = %152
  %156 = load ptr, ptr %9, align 8
  %157 = icmp eq ptr %156, null
  br i1 %157, label %158, label %160

158:                                              ; preds = %155
  %159 = load ptr, ptr %6, align 8
  store ptr %159, ptr %3, align 8
  br label %184

160:                                              ; preds = %155
  %161 = load ptr, ptr %6, align 8
  %162 = load ptr, ptr %10, align 8
  %163 = getelementptr inbounds %struct.cJSON, ptr %162, i32 0, i32 0
  store ptr %161, ptr %163, align 8
  %164 = load ptr, ptr %10, align 8
  %165 = load ptr, ptr %6, align 8
  %166 = getelementptr inbounds %struct.cJSON, ptr %165, i32 0, i32 1
  store ptr %164, ptr %166, align 8
  br label %167

167:                                              ; preds = %160, %152
  %168 = load ptr, ptr %7, align 8
  %169 = icmp ne ptr %168, null
  br i1 %169, label %170, label %182

170:                                              ; preds = %167
  %171 = load ptr, ptr %9, align 8
  %172 = icmp eq ptr %171, null
  br i1 %172, label %173, label %175

173:                                              ; preds = %170
  %174 = load ptr, ptr %7, align 8
  store ptr %174, ptr %3, align 8
  br label %184

175:                                              ; preds = %170
  %176 = load ptr, ptr %7, align 8
  %177 = load ptr, ptr %10, align 8
  %178 = getelementptr inbounds %struct.cJSON, ptr %177, i32 0, i32 0
  store ptr %176, ptr %178, align 8
  %179 = load ptr, ptr %10, align 8
  %180 = load ptr, ptr %7, align 8
  %181 = getelementptr inbounds %struct.cJSON, ptr %180, i32 0, i32 1
  store ptr %179, ptr %181, align 8
  br label %182

182:                                              ; preds = %175, %167
  %183 = load ptr, ptr %9, align 8
  store ptr %183, ptr %3, align 8
  br label %184

184:                                              ; preds = %182, %173, %158, %60, %23
  %185 = load ptr, ptr %3, align 8
  ret ptr %185
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @cJSONUtils_ApplyPatchesCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  store i32 0, ptr %7, align 4
  %8 = load ptr, ptr %5, align 8
  %9 = call i32 @cJSON_IsArray(ptr noundef %8)
  %10 = icmp ne i32 %9, 0
  br i1 %10, label %12, label %11

11:                                               ; preds = %2
  store i32 1, ptr %3, align 4
  br label %36

12:                                               ; preds = %2
  %13 = load ptr, ptr %5, align 8
  %14 = icmp ne ptr %13, null
  br i1 %14, label %15, label %19

15:                                               ; preds = %12
  %16 = load ptr, ptr %5, align 8
  %17 = getelementptr inbounds %struct.cJSON, ptr %16, i32 0, i32 2
  %18 = load ptr, ptr %17, align 8
  store ptr %18, ptr %6, align 8
  br label %19

19:                                               ; preds = %15, %12
  br label %20

20:                                               ; preds = %31, %19
  %21 = load ptr, ptr %6, align 8
  %22 = icmp ne ptr %21, null
  br i1 %22, label %23, label %35

23:                                               ; preds = %20
  %24 = load ptr, ptr %4, align 8
  %25 = load ptr, ptr %6, align 8
  %26 = call i32 @apply_patch(ptr noundef %24, ptr noundef %25, i32 noundef 1)
  store i32 %26, ptr %7, align 4
  %27 = load i32, ptr %7, align 4
  %28 = icmp ne i32 %27, 0
  br i1 %28, label %29, label %31

29:                                               ; preds = %23
  %30 = load i32, ptr %7, align 4
  store i32 %30, ptr %3, align 4
  br label %36

31:                                               ; preds = %23
  %32 = load ptr, ptr %6, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 0
  %34 = load ptr, ptr %33, align 8
  store ptr %34, ptr %6, align 8
  br label %20, !llvm.loop !60

35:                                               ; preds = %20
  store i32 0, ptr %3, align 4
  br label %36

36:                                               ; preds = %35, %29, %11
  %37 = load i32, ptr %3, align 4
  ret i32 %37
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSONUtils_AddPatchToArray(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3) #0 {
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store ptr %2, ptr %7, align 8
  store ptr %3, ptr %8, align 8
  %9 = load ptr, ptr %5, align 8
  %10 = load ptr, ptr %6, align 8
  %11 = load ptr, ptr %7, align 8
  %12 = load ptr, ptr %8, align 8
  call void @compose_patch(ptr noundef %9, ptr noundef %10, ptr noundef %11, ptr noundef null, ptr noundef %12)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @compose_patch(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, ptr noundef %4) #0 {
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca ptr, align 8
  %12 = alloca i64, align 8
  %13 = alloca i64, align 8
  %14 = alloca ptr, align 8
  store ptr %0, ptr %6, align 8
  store ptr %1, ptr %7, align 8
  store ptr %2, ptr %8, align 8
  store ptr %3, ptr %9, align 8
  store ptr %4, ptr %10, align 8
  store ptr null, ptr %11, align 8
  %15 = load ptr, ptr %6, align 8
  %16 = icmp eq ptr %15, null
  br i1 %16, label %23, label %17

17:                                               ; preds = %5
  %18 = load ptr, ptr %7, align 8
  %19 = icmp eq ptr %18, null
  br i1 %19, label %23, label %20

20:                                               ; preds = %17
  %21 = load ptr, ptr %8, align 8
  %22 = icmp eq ptr %21, null
  br i1 %22, label %23, label %24

23:                                               ; preds = %20, %17, %5
  br label %76

24:                                               ; preds = %20
  %25 = call ptr @cJSON_CreateObject()
  store ptr %25, ptr %11, align 8
  %26 = load ptr, ptr %11, align 8
  %27 = icmp eq ptr %26, null
  br i1 %27, label %28, label %29

28:                                               ; preds = %24
  br label %76

29:                                               ; preds = %24
  %30 = load ptr, ptr %11, align 8
  %31 = load ptr, ptr %7, align 8
  %32 = call ptr @cJSON_CreateString(ptr noundef %31)
  %33 = call i32 @cJSON_AddItemToObject(ptr noundef %30, ptr noundef @.str.6.20, ptr noundef %32)
  %34 = load ptr, ptr %9, align 8
  %35 = icmp eq ptr %34, null
  br i1 %35, label %36, label %41

36:                                               ; preds = %29
  %37 = load ptr, ptr %11, align 8
  %38 = load ptr, ptr %8, align 8
  %39 = call ptr @cJSON_CreateString(ptr noundef %38)
  %40 = call i32 @cJSON_AddItemToObject(ptr noundef %37, ptr noundef @.str.2.14, ptr noundef %39)
  br label %64

41:                                               ; preds = %29
  %42 = load ptr, ptr %9, align 8
  %43 = call i64 @pointer_encoded_length(ptr noundef %42)
  store i64 %43, ptr %12, align 8
  %44 = load ptr, ptr %8, align 8
  %45 = call i64 @strlen(ptr noundef %44) #9
  store i64 %45, ptr %13, align 8
  %46 = load i64, ptr %13, align 8
  %47 = load i64, ptr %12, align 8
  %48 = add i64 %46, %47
  %49 = add i64 %48, 2
  %50 = call ptr @cJSON_malloc(i64 noundef %49)
  store ptr %50, ptr %14, align 8
  %51 = load ptr, ptr %14, align 8
  %52 = load ptr, ptr %8, align 8
  %53 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %51, ptr noundef @.str.13, ptr noundef %52) #8
  %54 = load ptr, ptr %14, align 8
  %55 = load i64, ptr %13, align 8
  %56 = getelementptr inbounds i8, ptr %54, i64 %55
  %57 = getelementptr inbounds i8, ptr %56, i64 1
  %58 = load ptr, ptr %9, align 8
  call void @encode_string_as_pointer(ptr noundef %57, ptr noundef %58)
  %59 = load ptr, ptr %11, align 8
  %60 = load ptr, ptr %14, align 8
  %61 = call ptr @cJSON_CreateString(ptr noundef %60)
  %62 = call i32 @cJSON_AddItemToObject(ptr noundef %59, ptr noundef @.str.2.14, ptr noundef %61)
  %63 = load ptr, ptr %14, align 8
  call void @cJSON_free(ptr noundef %63)
  br label %64

64:                                               ; preds = %41, %36
  %65 = load ptr, ptr %10, align 8
  %66 = icmp ne ptr %65, null
  br i1 %66, label %67, label %72

67:                                               ; preds = %64
  %68 = load ptr, ptr %11, align 8
  %69 = load ptr, ptr %10, align 8
  %70 = call ptr @cJSON_Duplicate(ptr noundef %69, i32 noundef 1)
  %71 = call i32 @cJSON_AddItemToObject(ptr noundef %68, ptr noundef @.str.3.16, ptr noundef %70)
  br label %72

72:                                               ; preds = %67, %64
  %73 = load ptr, ptr %6, align 8
  %74 = load ptr, ptr %11, align 8
  %75 = call i32 @cJSON_AddItemToArray(ptr noundef %73, ptr noundef %74)
  br label %76

76:                                               ; preds = %72, %28, %23
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GeneratePatches(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = icmp eq ptr %7, null
  br i1 %8, label %12, label %9

9:                                                ; preds = %2
  %10 = load ptr, ptr %5, align 8
  %11 = icmp eq ptr %10, null
  br i1 %11, label %12, label %13

12:                                               ; preds = %9, %2
  store ptr null, ptr %3, align 8
  br label %19

13:                                               ; preds = %9
  %14 = call ptr @cJSON_CreateArray()
  store ptr %14, ptr %6, align 8
  %15 = load ptr, ptr %6, align 8
  %16 = load ptr, ptr %4, align 8
  %17 = load ptr, ptr %5, align 8
  call void @create_patches(ptr noundef %15, ptr noundef @.str.11, ptr noundef %16, ptr noundef %17, i32 noundef 0)
  %18 = load ptr, ptr %6, align 8
  store ptr %18, ptr %3, align 8
  br label %19

19:                                               ; preds = %13, %12
  %20 = load ptr, ptr %3, align 8
  ret ptr %20
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @create_patches(ptr noundef %0, ptr noundef %1, ptr noundef %2, ptr noundef %3, i32 noundef %4) #0 {
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca i32, align 4
  %11 = alloca i64, align 8
  %12 = alloca ptr, align 8
  %13 = alloca ptr, align 8
  %14 = alloca ptr, align 8
  %15 = alloca ptr, align 8
  %16 = alloca ptr, align 8
  %17 = alloca i32, align 4
  %18 = alloca i64, align 8
  %19 = alloca i64, align 8
  %20 = alloca ptr, align 8
  store ptr %0, ptr %6, align 8
  store ptr %1, ptr %7, align 8
  store ptr %2, ptr %8, align 8
  store ptr %3, ptr %9, align 8
  store i32 %4, ptr %10, align 4
  %21 = load ptr, ptr %8, align 8
  %22 = icmp eq ptr %21, null
  br i1 %22, label %26, label %23

23:                                               ; preds = %5
  %24 = load ptr, ptr %9, align 8
  %25 = icmp eq ptr %24, null
  br i1 %25, label %26, label %27

26:                                               ; preds = %23, %5
  br label %262

27:                                               ; preds = %23
  %28 = load ptr, ptr %8, align 8
  %29 = getelementptr inbounds %struct.cJSON, ptr %28, i32 0, i32 3
  %30 = load i32, ptr %29, align 8
  %31 = and i32 %30, 255
  %32 = load ptr, ptr %9, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 3
  %34 = load i32, ptr %33, align 8
  %35 = and i32 %34, 255
  %36 = icmp ne i32 %31, %35
  br i1 %36, label %37, label %41

37:                                               ; preds = %27
  %38 = load ptr, ptr %6, align 8
  %39 = load ptr, ptr %7, align 8
  %40 = load ptr, ptr %9, align 8
  call void @compose_patch(ptr noundef %38, ptr noundef @.str.9.23, ptr noundef %39, ptr noundef null, ptr noundef %40)
  br label %262

41:                                               ; preds = %27
  %42 = load ptr, ptr %8, align 8
  %43 = getelementptr inbounds %struct.cJSON, ptr %42, i32 0, i32 3
  %44 = load i32, ptr %43, align 8
  %45 = and i32 %44, 255
  switch i32 %45, label %261 [
    i32 8, label %46
    i32 16, label %68
    i32 32, label %82
    i32 64, label %162
  ]

46:                                               ; preds = %41
  %47 = load ptr, ptr %8, align 8
  %48 = getelementptr inbounds %struct.cJSON, ptr %47, i32 0, i32 5
  %49 = load i32, ptr %48, align 8
  %50 = load ptr, ptr %9, align 8
  %51 = getelementptr inbounds %struct.cJSON, ptr %50, i32 0, i32 5
  %52 = load i32, ptr %51, align 8
  %53 = icmp ne i32 %49, %52
  br i1 %53, label %63, label %54

54:                                               ; preds = %46
  %55 = load ptr, ptr %8, align 8
  %56 = getelementptr inbounds %struct.cJSON, ptr %55, i32 0, i32 6
  %57 = load double, ptr %56, align 8
  %58 = load ptr, ptr %9, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 6
  %60 = load double, ptr %59, align 8
  %61 = call i32 @compare_double.19(double noundef %57, double noundef %60)
  %62 = icmp ne i32 %61, 0
  br i1 %62, label %67, label %63

63:                                               ; preds = %54, %46
  %64 = load ptr, ptr %6, align 8
  %65 = load ptr, ptr %7, align 8
  %66 = load ptr, ptr %9, align 8
  call void @compose_patch(ptr noundef %64, ptr noundef @.str.9.23, ptr noundef %65, ptr noundef null, ptr noundef %66)
  br label %67

67:                                               ; preds = %63, %54
  br label %262

68:                                               ; preds = %41
  %69 = load ptr, ptr %8, align 8
  %70 = getelementptr inbounds %struct.cJSON, ptr %69, i32 0, i32 4
  %71 = load ptr, ptr %70, align 8
  %72 = load ptr, ptr %9, align 8
  %73 = getelementptr inbounds %struct.cJSON, ptr %72, i32 0, i32 4
  %74 = load ptr, ptr %73, align 8
  %75 = call i32 @strcmp(ptr noundef %71, ptr noundef %74) #9
  %76 = icmp ne i32 %75, 0
  br i1 %76, label %77, label %81

77:                                               ; preds = %68
  %78 = load ptr, ptr %6, align 8
  %79 = load ptr, ptr %7, align 8
  %80 = load ptr, ptr %9, align 8
  call void @compose_patch(ptr noundef %78, ptr noundef @.str.9.23, ptr noundef %79, ptr noundef null, ptr noundef %80)
  br label %81

81:                                               ; preds = %77, %68
  br label %262

82:                                               ; preds = %41
  store i64 0, ptr %11, align 8
  %83 = load ptr, ptr %8, align 8
  %84 = getelementptr inbounds %struct.cJSON, ptr %83, i32 0, i32 2
  %85 = load ptr, ptr %84, align 8
  store ptr %85, ptr %12, align 8
  %86 = load ptr, ptr %9, align 8
  %87 = getelementptr inbounds %struct.cJSON, ptr %86, i32 0, i32 2
  %88 = load ptr, ptr %87, align 8
  store ptr %88, ptr %13, align 8
  %89 = load ptr, ptr %7, align 8
  %90 = call i64 @strlen(ptr noundef %89) #9
  %91 = add i64 %90, 20
  %92 = add i64 %91, 2
  %93 = call ptr @cJSON_malloc(i64 noundef %92)
  store ptr %93, ptr %14, align 8
  store i64 0, ptr %11, align 8
  br label %94

94:                                               ; preds = %117, %82
  %95 = load ptr, ptr %12, align 8
  %96 = icmp ne ptr %95, null
  br i1 %96, label %97, label %100

97:                                               ; preds = %94
  %98 = load ptr, ptr %13, align 8
  %99 = icmp ne ptr %98, null
  br label %100

100:                                              ; preds = %97, %94
  %101 = phi i1 [ false, %94 ], [ %99, %97 ]
  br i1 %101, label %102, label %126

102:                                              ; preds = %100
  %103 = load i64, ptr %11, align 8
  %104 = icmp ugt i64 %103, -1
  br i1 %104, label %105, label %107

105:                                              ; preds = %102
  %106 = load ptr, ptr %14, align 8
  call void @cJSON_free(ptr noundef %106)
  br label %262

107:                                              ; preds = %102
  %108 = load ptr, ptr %14, align 8
  %109 = load ptr, ptr %7, align 8
  %110 = load i64, ptr %11, align 8
  %111 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %108, ptr noundef @.str.14, ptr noundef %109, i64 noundef %110) #8
  %112 = load ptr, ptr %6, align 8
  %113 = load ptr, ptr %14, align 8
  %114 = load ptr, ptr %12, align 8
  %115 = load ptr, ptr %13, align 8
  %116 = load i32, ptr %10, align 4
  call void @create_patches(ptr noundef %112, ptr noundef %113, ptr noundef %114, ptr noundef %115, i32 noundef %116)
  br label %117

117:                                              ; preds = %107
  %118 = load ptr, ptr %12, align 8
  %119 = getelementptr inbounds %struct.cJSON, ptr %118, i32 0, i32 0
  %120 = load ptr, ptr %119, align 8
  store ptr %120, ptr %12, align 8
  %121 = load ptr, ptr %13, align 8
  %122 = getelementptr inbounds %struct.cJSON, ptr %121, i32 0, i32 0
  %123 = load ptr, ptr %122, align 8
  store ptr %123, ptr %13, align 8
  %124 = load i64, ptr %11, align 8
  %125 = add i64 %124, 1
  store i64 %125, ptr %11, align 8
  br label %94, !llvm.loop !61

126:                                              ; preds = %100
  br label %127

127:                                              ; preds = %142, %126
  %128 = load ptr, ptr %12, align 8
  %129 = icmp ne ptr %128, null
  br i1 %129, label %130, label %146

130:                                              ; preds = %127
  %131 = load i64, ptr %11, align 8
  %132 = icmp ugt i64 %131, -1
  br i1 %132, label %133, label %135

133:                                              ; preds = %130
  %134 = load ptr, ptr %14, align 8
  call void @cJSON_free(ptr noundef %134)
  br label %262

135:                                              ; preds = %130
  %136 = load ptr, ptr %14, align 8
  %137 = load i64, ptr %11, align 8
  %138 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %136, ptr noundef @.str.15, i64 noundef %137) #8
  %139 = load ptr, ptr %6, align 8
  %140 = load ptr, ptr %7, align 8
  %141 = load ptr, ptr %14, align 8
  call void @compose_patch(ptr noundef %139, ptr noundef @.str.8.22, ptr noundef %140, ptr noundef %141, ptr noundef null)
  br label %142

142:                                              ; preds = %135
  %143 = load ptr, ptr %12, align 8
  %144 = getelementptr inbounds %struct.cJSON, ptr %143, i32 0, i32 0
  %145 = load ptr, ptr %144, align 8
  store ptr %145, ptr %12, align 8
  br label %127, !llvm.loop !62

146:                                              ; preds = %127
  br label %147

147:                                              ; preds = %154, %146
  %148 = load ptr, ptr %13, align 8
  %149 = icmp ne ptr %148, null
  br i1 %149, label %150, label %160

150:                                              ; preds = %147
  %151 = load ptr, ptr %6, align 8
  %152 = load ptr, ptr %7, align 8
  %153 = load ptr, ptr %13, align 8
  call void @compose_patch(ptr noundef %151, ptr noundef @.str.7.21, ptr noundef %152, ptr noundef @.str.5.18, ptr noundef %153)
  br label %154

154:                                              ; preds = %150
  %155 = load ptr, ptr %13, align 8
  %156 = getelementptr inbounds %struct.cJSON, ptr %155, i32 0, i32 0
  %157 = load ptr, ptr %156, align 8
  store ptr %157, ptr %13, align 8
  %158 = load i64, ptr %11, align 8
  %159 = add i64 %158, 1
  store i64 %159, ptr %11, align 8
  br label %147, !llvm.loop !63

160:                                              ; preds = %147
  %161 = load ptr, ptr %14, align 8
  call void @cJSON_free(ptr noundef %161)
  br label %262

162:                                              ; preds = %41
  store ptr null, ptr %15, align 8
  store ptr null, ptr %16, align 8
  %163 = load ptr, ptr %8, align 8
  %164 = load i32, ptr %10, align 4
  call void @sort_object(ptr noundef %163, i32 noundef %164)
  %165 = load ptr, ptr %9, align 8
  %166 = load i32, ptr %10, align 4
  call void @sort_object(ptr noundef %165, i32 noundef %166)
  %167 = load ptr, ptr %8, align 8
  %168 = getelementptr inbounds %struct.cJSON, ptr %167, i32 0, i32 2
  %169 = load ptr, ptr %168, align 8
  store ptr %169, ptr %15, align 8
  %170 = load ptr, ptr %9, align 8
  %171 = getelementptr inbounds %struct.cJSON, ptr %170, i32 0, i32 2
  %172 = load ptr, ptr %171, align 8
  store ptr %172, ptr %16, align 8
  br label %173

173:                                              ; preds = %259, %162
  %174 = load ptr, ptr %15, align 8
  %175 = icmp ne ptr %174, null
  br i1 %175, label %179, label %176

176:                                              ; preds = %173
  %177 = load ptr, ptr %16, align 8
  %178 = icmp ne ptr %177, null
  br label %179

179:                                              ; preds = %176, %173
  %180 = phi i1 [ true, %173 ], [ %178, %176 ]
  br i1 %180, label %181, label %260

181:                                              ; preds = %179
  %182 = load ptr, ptr %15, align 8
  %183 = icmp eq ptr %182, null
  br i1 %183, label %184, label %185

184:                                              ; preds = %181
  store i32 1, ptr %17, align 4
  br label %199

185:                                              ; preds = %181
  %186 = load ptr, ptr %16, align 8
  %187 = icmp eq ptr %186, null
  br i1 %187, label %188, label %189

188:                                              ; preds = %185
  store i32 -1, ptr %17, align 4
  br label %198

189:                                              ; preds = %185
  %190 = load ptr, ptr %15, align 8
  %191 = getelementptr inbounds %struct.cJSON, ptr %190, i32 0, i32 7
  %192 = load ptr, ptr %191, align 8
  %193 = load ptr, ptr %16, align 8
  %194 = getelementptr inbounds %struct.cJSON, ptr %193, i32 0, i32 7
  %195 = load ptr, ptr %194, align 8
  %196 = load i32, ptr %10, align 4
  %197 = call i32 @compare_strings(ptr noundef %192, ptr noundef %195, i32 noundef %196)
  store i32 %197, ptr %17, align 4
  br label %198

198:                                              ; preds = %189, %188
  br label %199

199:                                              ; preds = %198, %184
  %200 = load i32, ptr %17, align 4
  %201 = icmp eq i32 %200, 0
  br i1 %201, label %202, label %236

202:                                              ; preds = %199
  %203 = load ptr, ptr %7, align 8
  %204 = call i64 @strlen(ptr noundef %203) #9
  store i64 %204, ptr %18, align 8
  %205 = load ptr, ptr %15, align 8
  %206 = getelementptr inbounds %struct.cJSON, ptr %205, i32 0, i32 7
  %207 = load ptr, ptr %206, align 8
  %208 = call i64 @pointer_encoded_length(ptr noundef %207)
  store i64 %208, ptr %19, align 8
  %209 = load i64, ptr %18, align 8
  %210 = load i64, ptr %19, align 8
  %211 = add i64 %209, %210
  %212 = add i64 %211, 2
  %213 = call ptr @cJSON_malloc(i64 noundef %212)
  store ptr %213, ptr %20, align 8
  %214 = load ptr, ptr %20, align 8
  %215 = load ptr, ptr %7, align 8
  %216 = call i32 (ptr, ptr, ...) @sprintf(ptr noundef %214, ptr noundef @.str.13, ptr noundef %215) #8
  %217 = load ptr, ptr %20, align 8
  %218 = load i64, ptr %18, align 8
  %219 = getelementptr inbounds i8, ptr %217, i64 %218
  %220 = getelementptr inbounds i8, ptr %219, i64 1
  %221 = load ptr, ptr %15, align 8
  %222 = getelementptr inbounds %struct.cJSON, ptr %221, i32 0, i32 7
  %223 = load ptr, ptr %222, align 8
  call void @encode_string_as_pointer(ptr noundef %220, ptr noundef %223)
  %224 = load ptr, ptr %6, align 8
  %225 = load ptr, ptr %20, align 8
  %226 = load ptr, ptr %15, align 8
  %227 = load ptr, ptr %16, align 8
  %228 = load i32, ptr %10, align 4
  call void @create_patches(ptr noundef %224, ptr noundef %225, ptr noundef %226, ptr noundef %227, i32 noundef %228)
  %229 = load ptr, ptr %20, align 8
  call void @cJSON_free(ptr noundef %229)
  %230 = load ptr, ptr %15, align 8
  %231 = getelementptr inbounds %struct.cJSON, ptr %230, i32 0, i32 0
  %232 = load ptr, ptr %231, align 8
  store ptr %232, ptr %15, align 8
  %233 = load ptr, ptr %16, align 8
  %234 = getelementptr inbounds %struct.cJSON, ptr %233, i32 0, i32 0
  %235 = load ptr, ptr %234, align 8
  store ptr %235, ptr %16, align 8
  br label %259

236:                                              ; preds = %199
  %237 = load i32, ptr %17, align 4
  %238 = icmp slt i32 %237, 0
  br i1 %238, label %239, label %248

239:                                              ; preds = %236
  %240 = load ptr, ptr %6, align 8
  %241 = load ptr, ptr %7, align 8
  %242 = load ptr, ptr %15, align 8
  %243 = getelementptr inbounds %struct.cJSON, ptr %242, i32 0, i32 7
  %244 = load ptr, ptr %243, align 8
  call void @compose_patch(ptr noundef %240, ptr noundef @.str.8.22, ptr noundef %241, ptr noundef %244, ptr noundef null)
  %245 = load ptr, ptr %15, align 8
  %246 = getelementptr inbounds %struct.cJSON, ptr %245, i32 0, i32 0
  %247 = load ptr, ptr %246, align 8
  store ptr %247, ptr %15, align 8
  br label %258

248:                                              ; preds = %236
  %249 = load ptr, ptr %6, align 8
  %250 = load ptr, ptr %7, align 8
  %251 = load ptr, ptr %16, align 8
  %252 = getelementptr inbounds %struct.cJSON, ptr %251, i32 0, i32 7
  %253 = load ptr, ptr %252, align 8
  %254 = load ptr, ptr %16, align 8
  call void @compose_patch(ptr noundef %249, ptr noundef @.str.7.21, ptr noundef %250, ptr noundef %253, ptr noundef %254)
  %255 = load ptr, ptr %16, align 8
  %256 = getelementptr inbounds %struct.cJSON, ptr %255, i32 0, i32 0
  %257 = load ptr, ptr %256, align 8
  store ptr %257, ptr %16, align 8
  br label %258

258:                                              ; preds = %248, %239
  br label %259

259:                                              ; preds = %258, %202
  br label %173, !llvm.loop !64

260:                                              ; preds = %179
  br label %262

261:                                              ; preds = %41
  br label %262

262:                                              ; preds = %261, %260, %160, %133, %105, %81, %67, %37, %26
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GeneratePatchesCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  store ptr %1, ptr %5, align 8
  store ptr null, ptr %6, align 8
  %7 = load ptr, ptr %4, align 8
  %8 = icmp eq ptr %7, null
  br i1 %8, label %12, label %9

9:                                                ; preds = %2
  %10 = load ptr, ptr %5, align 8
  %11 = icmp eq ptr %10, null
  br i1 %11, label %12, label %13

12:                                               ; preds = %9, %2
  store ptr null, ptr %3, align 8
  br label %19

13:                                               ; preds = %9
  %14 = call ptr @cJSON_CreateArray()
  store ptr %14, ptr %6, align 8
  %15 = load ptr, ptr %6, align 8
  %16 = load ptr, ptr %4, align 8
  %17 = load ptr, ptr %5, align 8
  call void @create_patches(ptr noundef %15, ptr noundef @.str.11, ptr noundef %16, ptr noundef %17, i32 noundef 1)
  %18 = load ptr, ptr %6, align 8
  store ptr %18, ptr %3, align 8
  br label %19

19:                                               ; preds = %13, %12
  %20 = load ptr, ptr %3, align 8
  ret ptr %20
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSONUtils_SortObject(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  call void @sort_object(ptr noundef %3, i32 noundef 0)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @cJSONUtils_SortObjectCaseSensitive(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  call void @sort_object(ptr noundef %3, i32 noundef 1)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_MergePatch(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @merge_patch(ptr noundef %5, ptr noundef %6, i32 noundef 0)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @merge_patch(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  store ptr null, ptr %8, align 8
  %11 = load ptr, ptr %6, align 8
  %12 = call i32 @cJSON_IsObject(ptr noundef %11)
  %13 = icmp ne i32 %12, 0
  br i1 %13, label %18, label %14

14:                                               ; preds = %3
  %15 = load ptr, ptr %5, align 8
  call void @cJSON_Delete(ptr noundef %15)
  %16 = load ptr, ptr %6, align 8
  %17 = call ptr @cJSON_Duplicate(ptr noundef %16, i32 noundef 1)
  store ptr %17, ptr %4, align 8
  br label %87

18:                                               ; preds = %3
  %19 = load ptr, ptr %5, align 8
  %20 = call i32 @cJSON_IsObject(ptr noundef %19)
  %21 = icmp ne i32 %20, 0
  br i1 %21, label %25, label %22

22:                                               ; preds = %18
  %23 = load ptr, ptr %5, align 8
  call void @cJSON_Delete(ptr noundef %23)
  %24 = call ptr @cJSON_CreateObject()
  store ptr %24, ptr %5, align 8
  br label %25

25:                                               ; preds = %22, %18
  %26 = load ptr, ptr %6, align 8
  %27 = getelementptr inbounds %struct.cJSON, ptr %26, i32 0, i32 2
  %28 = load ptr, ptr %27, align 8
  store ptr %28, ptr %8, align 8
  br label %29

29:                                               ; preds = %81, %25
  %30 = load ptr, ptr %8, align 8
  %31 = icmp ne ptr %30, null
  br i1 %31, label %32, label %85

32:                                               ; preds = %29
  %33 = load ptr, ptr %8, align 8
  %34 = call i32 @cJSON_IsNull(ptr noundef %33)
  %35 = icmp ne i32 %34, 0
  br i1 %35, label %36, label %50

36:                                               ; preds = %32
  %37 = load i32, ptr %7, align 4
  %38 = icmp ne i32 %37, 0
  br i1 %38, label %39, label %44

39:                                               ; preds = %36
  %40 = load ptr, ptr %5, align 8
  %41 = load ptr, ptr %8, align 8
  %42 = getelementptr inbounds %struct.cJSON, ptr %41, i32 0, i32 7
  %43 = load ptr, ptr %42, align 8
  call void @cJSON_DeleteItemFromObjectCaseSensitive(ptr noundef %40, ptr noundef %43)
  br label %49

44:                                               ; preds = %36
  %45 = load ptr, ptr %5, align 8
  %46 = load ptr, ptr %8, align 8
  %47 = getelementptr inbounds %struct.cJSON, ptr %46, i32 0, i32 7
  %48 = load ptr, ptr %47, align 8
  call void @cJSON_DeleteItemFromObject(ptr noundef %45, ptr noundef %48)
  br label %49

49:                                               ; preds = %44, %39
  br label %81

50:                                               ; preds = %32
  store ptr null, ptr %9, align 8
  store ptr null, ptr %10, align 8
  %51 = load i32, ptr %7, align 4
  %52 = icmp ne i32 %51, 0
  br i1 %52, label %53, label %59

53:                                               ; preds = %50
  %54 = load ptr, ptr %5, align 8
  %55 = load ptr, ptr %8, align 8
  %56 = getelementptr inbounds %struct.cJSON, ptr %55, i32 0, i32 7
  %57 = load ptr, ptr %56, align 8
  %58 = call ptr @cJSON_DetachItemFromObjectCaseSensitive(ptr noundef %54, ptr noundef %57)
  store ptr %58, ptr %9, align 8
  br label %65

59:                                               ; preds = %50
  %60 = load ptr, ptr %5, align 8
  %61 = load ptr, ptr %8, align 8
  %62 = getelementptr inbounds %struct.cJSON, ptr %61, i32 0, i32 7
  %63 = load ptr, ptr %62, align 8
  %64 = call ptr @cJSON_DetachItemFromObject(ptr noundef %60, ptr noundef %63)
  store ptr %64, ptr %9, align 8
  br label %65

65:                                               ; preds = %59, %53
  %66 = load ptr, ptr %9, align 8
  %67 = load ptr, ptr %8, align 8
  %68 = load i32, ptr %7, align 4
  %69 = call ptr @merge_patch(ptr noundef %66, ptr noundef %67, i32 noundef %68)
  store ptr %69, ptr %10, align 8
  %70 = load ptr, ptr %10, align 8
  %71 = icmp eq ptr %70, null
  br i1 %71, label %72, label %74

72:                                               ; preds = %65
  %73 = load ptr, ptr %5, align 8
  call void @cJSON_Delete(ptr noundef %73)
  store ptr null, ptr %4, align 8
  br label %87

74:                                               ; preds = %65
  %75 = load ptr, ptr %5, align 8
  %76 = load ptr, ptr %8, align 8
  %77 = getelementptr inbounds %struct.cJSON, ptr %76, i32 0, i32 7
  %78 = load ptr, ptr %77, align 8
  %79 = load ptr, ptr %10, align 8
  %80 = call i32 @cJSON_AddItemToObject(ptr noundef %75, ptr noundef %78, ptr noundef %79)
  br label %81

81:                                               ; preds = %74, %49
  %82 = load ptr, ptr %8, align 8
  %83 = getelementptr inbounds %struct.cJSON, ptr %82, i32 0, i32 0
  %84 = load ptr, ptr %83, align 8
  store ptr %84, ptr %8, align 8
  br label %29, !llvm.loop !65

85:                                               ; preds = %29
  %86 = load ptr, ptr %5, align 8
  store ptr %86, ptr %4, align 8
  br label %87

87:                                               ; preds = %85, %72, %14
  %88 = load ptr, ptr %4, align 8
  ret ptr %88
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_MergePatchCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @merge_patch(ptr noundef %5, ptr noundef %6, i32 noundef 1)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GenerateMergePatch(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @generate_merge_patch(ptr noundef %5, ptr noundef %6, i32 noundef 0)
  ret ptr %7
}

; Function Attrs: noinline nounwind optnone uwtable
define internal ptr @generate_merge_patch(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 8
  %9 = alloca ptr, align 8
  %10 = alloca ptr, align 8
  %11 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  store ptr %1, ptr %6, align 8
  store i32 %2, ptr %7, align 4
  store ptr null, ptr %8, align 8
  store ptr null, ptr %9, align 8
  store ptr null, ptr %10, align 8
  %12 = load ptr, ptr %6, align 8
  %13 = icmp eq ptr %12, null
  br i1 %13, label %14, label %16

14:                                               ; preds = %3
  %15 = call ptr @cJSON_CreateNull()
  store ptr %15, ptr %4, align 8
  br label %128

16:                                               ; preds = %3
  %17 = load ptr, ptr %6, align 8
  %18 = call i32 @cJSON_IsObject(ptr noundef %17)
  %19 = icmp ne i32 %18, 0
  br i1 %19, label %20, label %24

20:                                               ; preds = %16
  %21 = load ptr, ptr %5, align 8
  %22 = call i32 @cJSON_IsObject(ptr noundef %21)
  %23 = icmp ne i32 %22, 0
  br i1 %23, label %27, label %24

24:                                               ; preds = %20, %16
  %25 = load ptr, ptr %6, align 8
  %26 = call ptr @cJSON_Duplicate(ptr noundef %25, i32 noundef 1)
  store ptr %26, ptr %4, align 8
  br label %128

27:                                               ; preds = %20
  %28 = load ptr, ptr %5, align 8
  %29 = load i32, ptr %7, align 4
  call void @sort_object(ptr noundef %28, i32 noundef %29)
  %30 = load ptr, ptr %6, align 8
  %31 = load i32, ptr %7, align 4
  call void @sort_object(ptr noundef %30, i32 noundef %31)
  %32 = load ptr, ptr %5, align 8
  %33 = getelementptr inbounds %struct.cJSON, ptr %32, i32 0, i32 2
  %34 = load ptr, ptr %33, align 8
  store ptr %34, ptr %8, align 8
  %35 = load ptr, ptr %6, align 8
  %36 = getelementptr inbounds %struct.cJSON, ptr %35, i32 0, i32 2
  %37 = load ptr, ptr %36, align 8
  store ptr %37, ptr %9, align 8
  %38 = call ptr @cJSON_CreateObject()
  store ptr %38, ptr %10, align 8
  %39 = load ptr, ptr %10, align 8
  %40 = icmp eq ptr %39, null
  br i1 %40, label %41, label %42

41:                                               ; preds = %27
  store ptr null, ptr %4, align 8
  br label %128

42:                                               ; preds = %27
  br label %43

43:                                               ; preds = %118, %42
  %44 = load ptr, ptr %8, align 8
  %45 = icmp ne ptr %44, null
  br i1 %45, label %49, label %46

46:                                               ; preds = %43
  %47 = load ptr, ptr %9, align 8
  %48 = icmp ne ptr %47, null
  br label %49

49:                                               ; preds = %46, %43
  %50 = phi i1 [ true, %43 ], [ %48, %46 ]
  br i1 %50, label %51, label %119

51:                                               ; preds = %49
  %52 = load ptr, ptr %8, align 8
  %53 = icmp ne ptr %52, null
  br i1 %53, label %54, label %67

54:                                               ; preds = %51
  %55 = load ptr, ptr %9, align 8
  %56 = icmp ne ptr %55, null
  br i1 %56, label %57, label %65

57:                                               ; preds = %54
  %58 = load ptr, ptr %8, align 8
  %59 = getelementptr inbounds %struct.cJSON, ptr %58, i32 0, i32 7
  %60 = load ptr, ptr %59, align 8
  %61 = load ptr, ptr %9, align 8
  %62 = getelementptr inbounds %struct.cJSON, ptr %61, i32 0, i32 7
  %63 = load ptr, ptr %62, align 8
  %64 = call i32 @strcmp(ptr noundef %60, ptr noundef %63) #9
  store i32 %64, ptr %11, align 4
  br label %66

65:                                               ; preds = %54
  store i32 -1, ptr %11, align 4
  br label %66

66:                                               ; preds = %65, %57
  br label %68

67:                                               ; preds = %51
  store i32 1, ptr %11, align 4
  br label %68

68:                                               ; preds = %67, %66
  %69 = load i32, ptr %11, align 4
  %70 = icmp slt i32 %69, 0
  br i1 %70, label %71, label %81

71:                                               ; preds = %68
  %72 = load ptr, ptr %10, align 8
  %73 = load ptr, ptr %8, align 8
  %74 = getelementptr inbounds %struct.cJSON, ptr %73, i32 0, i32 7
  %75 = load ptr, ptr %74, align 8
  %76 = call ptr @cJSON_CreateNull()
  %77 = call i32 @cJSON_AddItemToObject(ptr noundef %72, ptr noundef %75, ptr noundef %76)
  %78 = load ptr, ptr %8, align 8
  %79 = getelementptr inbounds %struct.cJSON, ptr %78, i32 0, i32 0
  %80 = load ptr, ptr %79, align 8
  store ptr %80, ptr %8, align 8
  br label %118

81:                                               ; preds = %68
  %82 = load i32, ptr %11, align 4
  %83 = icmp sgt i32 %82, 0
  br i1 %83, label %84, label %95

84:                                               ; preds = %81
  %85 = load ptr, ptr %10, align 8
  %86 = load ptr, ptr %9, align 8
  %87 = getelementptr inbounds %struct.cJSON, ptr %86, i32 0, i32 7
  %88 = load ptr, ptr %87, align 8
  %89 = load ptr, ptr %9, align 8
  %90 = call ptr @cJSON_Duplicate(ptr noundef %89, i32 noundef 1)
  %91 = call i32 @cJSON_AddItemToObject(ptr noundef %85, ptr noundef %88, ptr noundef %90)
  %92 = load ptr, ptr %9, align 8
  %93 = getelementptr inbounds %struct.cJSON, ptr %92, i32 0, i32 0
  %94 = load ptr, ptr %93, align 8
  store ptr %94, ptr %9, align 8
  br label %117

95:                                               ; preds = %81
  %96 = load ptr, ptr %8, align 8
  %97 = load ptr, ptr %9, align 8
  %98 = load i32, ptr %7, align 4
  %99 = call i32 @compare_json(ptr noundef %96, ptr noundef %97, i32 noundef %98)
  %100 = icmp ne i32 %99, 0
  br i1 %100, label %110, label %101

101:                                              ; preds = %95
  %102 = load ptr, ptr %10, align 8
  %103 = load ptr, ptr %9, align 8
  %104 = getelementptr inbounds %struct.cJSON, ptr %103, i32 0, i32 7
  %105 = load ptr, ptr %104, align 8
  %106 = load ptr, ptr %8, align 8
  %107 = load ptr, ptr %9, align 8
  %108 = call ptr @cJSONUtils_GenerateMergePatch(ptr noundef %106, ptr noundef %107)
  %109 = call i32 @cJSON_AddItemToObject(ptr noundef %102, ptr noundef %105, ptr noundef %108)
  br label %110

110:                                              ; preds = %101, %95
  %111 = load ptr, ptr %8, align 8
  %112 = getelementptr inbounds %struct.cJSON, ptr %111, i32 0, i32 0
  %113 = load ptr, ptr %112, align 8
  store ptr %113, ptr %8, align 8
  %114 = load ptr, ptr %9, align 8
  %115 = getelementptr inbounds %struct.cJSON, ptr %114, i32 0, i32 0
  %116 = load ptr, ptr %115, align 8
  store ptr %116, ptr %9, align 8
  br label %117

117:                                              ; preds = %110, %84
  br label %118

118:                                              ; preds = %117, %71
  br label %43, !llvm.loop !66

119:                                              ; preds = %49
  %120 = load ptr, ptr %10, align 8
  %121 = getelementptr inbounds %struct.cJSON, ptr %120, i32 0, i32 2
  %122 = load ptr, ptr %121, align 8
  %123 = icmp eq ptr %122, null
  br i1 %123, label %124, label %126

124:                                              ; preds = %119
  %125 = load ptr, ptr %10, align 8
  call void @cJSON_Delete(ptr noundef %125)
  store ptr null, ptr %4, align 8
  br label %128

126:                                              ; preds = %119
  %127 = load ptr, ptr %10, align 8
  store ptr %127, ptr %4, align 8
  br label %128

128:                                              ; preds = %126, %124, %41, %24, %14
  %129 = load ptr, ptr %4, align 8
  ret ptr %129
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local ptr @cJSONUtils_GenerateMergePatchCaseSensitive(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call ptr @generate_merge_patch(ptr noundef %5, ptr noundef %6, i32 noundef 1)
  ret ptr %7
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
attributes #1 = { nounwind "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
attributes #2 = { nounwind allocsize(0) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
attributes #3 = { nounwind allocsize(1) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
attributes #4 = { nounwind willreturn memory(read) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+outline-atomics,+v8a,-fmv" }
attributes #5 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #6 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #7 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #8 = { nounwind }
attributes #9 = { nounwind willreturn memory(read) }
attributes #10 = { memory(none) }

!llvm.ident = !{!0, !0}
!llvm.module.flags = !{!1, !2, !3, !4, !5}

!0 = !{!"clang version 16.0.4 (https://github.com/bjjwwang/LLVM-compile aed81d25b4818ed2645b53ffaed7664c1437b458)"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 8, !"PIC Level", i32 2}
!3 = !{i32 7, !"PIE Level", i32 2}
!4 = !{i32 7, !"uwtable", i32 2}
!5 = !{i32 7, !"frame-pointer", i32 1}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = distinct !{!8, !7}
!9 = distinct !{!9, !7}
!10 = distinct !{!10, !7}
!11 = distinct !{!11, !7}
!12 = distinct !{!12, !7}
!13 = distinct !{!13, !7}
!14 = distinct !{!14, !7}
!15 = distinct !{!15, !7}
!16 = distinct !{!16, !7}
!17 = distinct !{!17, !7}
!18 = distinct !{!18, !7}
!19 = distinct !{!19, !7}
!20 = distinct !{!20, !7}
!21 = distinct !{!21, !7}
!22 = distinct !{!22, !7}
!23 = distinct !{!23, !7}
!24 = distinct !{!24, !7}
!25 = distinct !{!25, !7}
!26 = distinct !{!26, !7}
!27 = distinct !{!27, !7}
!28 = distinct !{!28, !7}
!29 = distinct !{!29, !7}
!30 = distinct !{!30, !7}
!31 = distinct !{!31, !7}
!32 = distinct !{!32, !7}
!33 = distinct !{!33, !7}
!34 = distinct !{!34, !7}
!35 = distinct !{!35, !7}
!36 = distinct !{!36, !7}
!37 = distinct !{!37, !7}
!38 = distinct !{!38, !7}
!39 = distinct !{!39, !7}
!40 = distinct !{!40, !7}
!41 = distinct !{!41, !7}
!42 = distinct !{!42, !7}
!43 = distinct !{!43, !7}
!44 = distinct !{!44, !7}
!45 = distinct !{!45, !7}
!46 = distinct !{!46, !7}
!47 = distinct !{!47, !7}
!48 = distinct !{!48, !7}
!49 = distinct !{!49, !7}
!50 = distinct !{!50, !7}
!51 = distinct !{!51, !7}
!52 = distinct !{!52, !7}
!53 = distinct !{!53, !7}
!54 = distinct !{!54, !7}
!55 = distinct !{!55, !7}
!56 = distinct !{!56, !7}
!57 = distinct !{!57, !7}
!58 = distinct !{!58, !7}
!59 = distinct !{!59, !7}
!60 = distinct !{!60, !7}
!61 = distinct !{!61, !7}
!62 = distinct !{!62, !7}
!63 = distinct !{!63, !7}
!64 = distinct !{!64, !7}
!65 = distinct !{!65, !7}
!66 = distinct !{!66, !7}
