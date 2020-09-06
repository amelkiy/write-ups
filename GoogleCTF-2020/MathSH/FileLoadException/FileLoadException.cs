using System;

namespace FileLoadException
{
	public class MyTest : MarshalByRefObject{
		~MyTest(){
			throw new Exception();
		}
	}
	public class FileLoadException
    {
        public MyTest GetSpecialClass(){
            return new MyTest();
        }
	}
}
