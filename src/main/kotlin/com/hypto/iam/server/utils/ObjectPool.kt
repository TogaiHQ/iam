package com.hypto.iam.server.utils

import kotlin.math.abs
import kotlin.random.Random
import kotlin.reflect.KFunction

class ObjectPool<T>(
    initialPoolSize: Int = 5,
    private val constructorFn: KFunction<T>,
    private val getInUseObjectsIfNotAvailable: Boolean = false,
    vararg args: Any?,
) {
    private var poolSize: Int = initialPoolSize
        private set(value) {
            if (field != value) {
                val diff = value - field
                field = value
                updatePoolObjectCount(diff)
            }
        }

    private val constructorArgs = args

    @Synchronized
    fun availableSize() = available.count()

    @Synchronized
    fun usingSize() = inUse.count()

    private val available = mutableListOf<T>()
    private val inUse = mutableListOf<T>()

    init {
        createInitialObjects()
    }

    private fun createObject(): T {
        return if (constructorArgs.isEmpty()) {
            constructorFn.call()
        } else {
            constructorFn.call(constructorArgs)
        }
    }

    private fun createInitialObjects() {
        for (i in 0 until poolSize) available.add(createObject())
    }

    @Synchronized
    private fun updatePoolObjectCount(difference: Int) {
        if (difference < 0) {
            // decrease pool size by difference
            if (availableSize() > abs(difference)) {
                for (i in 0 until abs(difference)) available.removeAt(i)
            } else {
                available.clear()
            }
        } else {
            // increase pool size by difference
            for (i in 0 until difference) available.add(createObject())
        }
    }

    @Synchronized
    fun borrowObject(): T? {
        return if (availableSize() > 0) {
            val item = available[0]
            available.removeAt(0)
            inUse.add(item)
            item
        } else if (getInUseObjectsIfNotAvailable) {
            inUse[Random.nextInt(inUse.size)]
        } else {
            null
        }
    }

    @Synchronized
    fun recycleObject(item: T) {
        if (availableSize() + 1 <= poolSize) available.add(item)
        inUse.remove(item)
    }

//    companion object {
//        @Volatile
//        private var instance: ObjectPool? = null
//
//        @Synchronized
//        fun getInstance(initialPoolSize: Int = 10): ObjectPool {
//            val result = instance ?: ObjectPool(initialPoolSize).also { instance = it }
//            result.poolSize = initialPoolSize
//            return result
//        }
//    }
}
