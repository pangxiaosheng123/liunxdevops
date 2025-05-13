def escape_single_quotes_in_sql(sql):
    in_string = False
    result = []
    for char in sql:
        if char == "'":
            if in_string:
                result.extend(["'", "'"])
            else:
                result.append(char)
            in_string = not in_string
        else:
            result.append(char)
    return ''.join(result)


input_file_path = 'D:/redo/code/181.sql'
output_file_path = 'D:/redo/code/1811.sql'

try:
    with open(input_file_path, 'r', encoding='utf-8') as infile:
        sql_lines = infile.readlines()

    escaped_lines = [escape_single_quotes_in_sql(line) for line in sql_lines]

    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        outfile.writelines(escaped_lines)

    print(f"处理完成，结果已保存到 {output_file_path}。")

except FileNotFoundError:
    print(f"未找到 {input_file_path} 文件，请检查文件路径。")
except Exception as e:
    print(f"处理过程中出现错误: {e}")
